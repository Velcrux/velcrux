//! High-Level NIC Memory Fabric Coordinator (ADR-083).
//!
//! Orchestrates the UMEM pool, AF_XDP ring pairs, wire-speed QUIC demuxer,
//! and hardware DMA descriptors into an autonomous zero-copy kernel-bypass pipeline.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::demux::NicPacketDemuxer;
use super::rings::NicRingSet;
use super::types::{
    NicDriverMode, NicError, NicFrameState, NicPacketDescriptor, NicQuicPacketView, NicResult,
    NicStatus, NicUmemConfig,
};
use super::umem::NicUmemPool;

/// The central controller coordinating AF_XDP rings, UMEM buffers, and zero-copy packet dispatch.
pub struct NicMemoryFabric {
    interface_name: String,
    driver_mode: NicDriverMode,
    umem: Arc<NicUmemPool>,
    rings: NicRingSet,
    total_rx_packets: AtomicU64,
    total_tx_packets: AtomicU64,
    total_rx_bytes: AtomicU64,
    total_tx_bytes: AtomicU64,
    dropped_packets: AtomicU64,
}

impl NicMemoryFabric {
    /// Initialize a new NIC Memory Fabric bound to the given interface.
    pub fn new(
        interface_name: impl Into<String>,
        driver_mode: NicDriverMode,
        config: NicUmemConfig,
    ) -> NicResult<Self> {
        let umem = Arc::new(NicUmemPool::new(config.clone())?);
        let rings = NicRingSet::new(
            config.fill_ring_size,
            config.rx_ring_size,
            config.tx_ring_size,
            config.completion_ring_size,
        );

        let fabric = Self {
            interface_name: interface_name.into(),
            driver_mode,
            umem,
            rings,
            total_rx_packets: AtomicU64::new(0),
            total_tx_packets: AtomicU64::new(0),
            total_rx_bytes: AtomicU64::new(0),
            total_tx_bytes: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
        };

        // Initial fill ring priming: pass initial free frames to fill ring
        fabric.replenish_fill_ring(config.fill_ring_size.min(config.total_frames / 2))?;

        Ok(fabric)
    }

    /// Bound network interface name.
    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Active driver mode.
    #[must_use]
    pub fn driver_mode(&self) -> NicDriverMode {
        self.driver_mode
    }

    /// Access the underlying UMEM pool.
    #[must_use]
    pub fn umem(&self) -> &Arc<NicUmemPool> {
        &self.umem
    }

    /// Access the AF_XDP ring sets.
    #[must_use]
    pub fn rings(&self) -> &NicRingSet {
        &self.rings
    }

    /// Reclaim transmitted frames from the Completion Ring and return them to the UMEM free pool.
    pub fn reclaim_completion_frames(&self) -> usize {
        let addrs = self
            .rings
            .completion
            .dequeue_batch(self.rings.completion.len());
        let count = addrs.len();
        for addr in addrs {
            let frame_idx = self.umem.addr_to_frame_index(addr);
            let _ = self.umem.free_frame(frame_idx);
        }
        count
    }

    /// Replenish the Fill Ring with free frame addresses so NIC DMA never starves.
    pub fn replenish_fill_ring(&self, max_frames: usize) -> NicResult<usize> {
        let available_slots = self.rings.fill.available_slots();
        let free_in_umem = self.umem.free_frames_count();
        let count = max_frames.min(available_slots).min(free_in_umem);

        if count == 0 {
            return Ok(0);
        }

        let frame_indices = self.umem.alloc_batch(count, NicFrameState::InFillRing)?;
        let addrs: Vec<u64> = frame_indices
            .iter()
            .map(|&idx| self.umem.packet_addr(idx))
            .collect();

        let queued = self.rings.fill.enqueue_batch(&addrs);
        // If ring overflowed unexpectedly, release unqueued frames
        if queued < count {
            for &idx in &frame_indices[queued..] {
                let _ = self.umem.free_frame(idx);
            }
        }
        Ok(queued)
    }

    /// Ingest a burst of incoming packet descriptors from the Rx Ring and demux them into QUIC packet views.
    pub fn receive_burst(&self, max_burst: usize) -> Vec<NicQuicPacketView> {
        // Step 1: Reclaim completed TX frames
        let _ = self.reclaim_completion_frames();

        // Step 2: Replenish fill ring
        let _ = self.replenish_fill_ring(max_burst);

        // Step 3: Dequeue packet descriptors from Rx Ring
        let descriptors = self.rings.rx.dequeue_batch(max_burst);
        let mut views = Vec::with_capacity(descriptors.len());

        for desc in descriptors {
            let frame_idx = self.umem.addr_to_frame_index(desc.addr);
            let parse_result = self.umem.with_packet_slice(frame_idx, |slice| {
                let wire_slice = if (desc.len as usize) <= slice.len() {
                    &slice[..desc.len as usize]
                } else {
                    slice
                };
                NicPacketDemuxer::parse_frame(frame_idx, wire_slice)
            });

            match parse_result {
                Ok(Ok(view)) => {
                    let _ = self
                        .umem
                        .update_frame_state(frame_idx, NicFrameState::DispatchedToQuic);
                    self.total_rx_packets.fetch_add(1, Ordering::Relaxed);
                    self.total_rx_bytes
                        .fetch_add(desc.len as u64, Ordering::Relaxed);
                    views.push(view);
                }
                _ => {
                    // Parsing error or invalid frame: drop frame and return to pool
                    self.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    let _ = self.umem.free_frame(frame_idx);
                }
            }
        }

        views
    }

    /// Enqueue an outgoing wire packet directly into the Tx Ring without memory allocation.
    pub fn transmit_packet(&self, raw_data: &[u8]) -> NicResult<usize> {
        let frame_idx = self.umem.alloc_frame(NicFrameState::InTxRing)?;
        let bytes_written = self.umem.write_packet(frame_idx, raw_data)?;
        let addr = self.umem.packet_addr(frame_idx);

        let desc = NicPacketDescriptor::new(addr, bytes_written as u32, 0);
        if let Err(e) = self.rings.tx.enqueue(desc) {
            let _ = self.umem.free_frame(frame_idx);
            return Err(e);
        }

        self.total_tx_packets.fetch_add(1, Ordering::Relaxed);
        self.total_tx_bytes
            .fetch_add(bytes_written as u64, Ordering::Relaxed);
        Ok(frame_idx)
    }

    /// Simulate hardware DMA packet arrival (useful for testing and cross-platform verification).
    pub fn simulate_ingress_packet(&self, raw_packet: &[u8]) -> NicResult<usize> {
        // Pop a frame address from fill ring (as NIC DMA would)
        let addr = match self.rings.fill.dequeue() {
            Some(a) => a,
            None => {
                // If fill ring was empty, try to replenish immediately
                self.replenish_fill_ring(16)?;
                self.rings
                    .fill
                    .dequeue()
                    .ok_or_else(|| NicError::InterfaceError {
                        interface: self.interface_name.clone(),
                        message: "NIC hardware DMA starved: Fill Ring empty".to_string(),
                    })?
            }
        };

        let frame_idx = self.umem.addr_to_frame_index(addr);
        let bytes_written = self.umem.write_packet(frame_idx, raw_packet)?;
        let _ = self
            .umem
            .update_frame_state(frame_idx, NicFrameState::ReceivedIngress);

        let desc = NicPacketDescriptor::new(addr, bytes_written as u32, 0);
        self.rings.rx.enqueue(desc)?;
        Ok(frame_idx)
    }

    /// Simulate hardware completion of transmitted packets.
    pub fn simulate_tx_completion(&self, max_packets: usize) -> usize {
        let descs = self.rings.tx.dequeue_batch(max_packets);
        let count = descs.len();
        for desc in descs {
            let _ = self.rings.completion.enqueue(desc.addr);
        }
        count
    }

    /// Snapshot real-time telemetry and health metrics.
    #[must_use]
    pub fn status(&self) -> NicStatus {
        let total_frames = self.umem.config().total_frames;
        let in_flight = self.umem.in_flight_count();
        let free = self.umem.free_frames_count();
        let util = (in_flight as f64 / total_frames as f64) * 100.0;

        NicStatus {
            interface_name: self.interface_name.clone(),
            driver_mode: self.driver_mode,
            zero_copy_active: self.driver_mode.is_zero_copy(),
            umem_total_bytes: self.umem.total_bytes(),
            umem_total_frames: total_frames,
            frames_in_flight: in_flight,
            frames_free: free,
            umem_utilization_percent: util,
            fill_ring_count: self.rings.fill.len(),
            rx_ring_count: self.rings.rx.len(),
            tx_ring_count: self.rings.tx.len(),
            completion_ring_count: self.rings.completion.len(),
            total_rx_packets: self.total_rx_packets.load(Ordering::Relaxed),
            total_tx_packets: self.total_tx_packets.load(Ordering::Relaxed),
            total_rx_bytes: self.total_rx_bytes.load(Ordering::Relaxed),
            total_tx_bytes: self.total_tx_bytes.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
        }
    }
}
