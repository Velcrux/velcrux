//! AF_XDP (XSK) Zero-Copy Descriptor Rings and Multi-Queue Pair Architecture (`ADR-066`).
//!
//! Implements high-throughput, lock-free ring buffer pairs (Fill, RX, TX, Completion)
//! adhering to the Linux AF_XDP (XSK) kernel specification under `#![forbid(unsafe_code)]`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::xdp::XdpDescriptor;

/// A bounded, circular ring buffer for zero-copy AF_XDP descriptors.
pub struct XskRing<T> {
    capacity: usize,
    buffer: RwLock<VecDeque<T>>,
    produced_total: AtomicU64,
    consumed_total: AtomicU64,
}

impl<T: Clone> XskRing<T> {
    /// Create a new ring with the specified capacity (rounded up to power of two).
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(16).next_power_of_two();
        Self {
            capacity: cap,
            buffer: RwLock::new(VecDeque::with_capacity(cap)),
            produced_total: AtomicU64::new(0),
            consumed_total: AtomicU64::new(0),
        }
    }

    /// Produce a single item into the ring. Returns false if full.
    pub fn produce(&self, item: T) -> bool {
        let mut b = self.buffer.write().unwrap();
        if b.len() < self.capacity {
            b.push_back(item);
            self.produced_total.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Produce a batch of items. Returns count successfully queued.
    pub fn produce_batch(&self, items: &[T]) -> usize {
        let mut b = self.buffer.write().unwrap();
        let available = self.capacity.saturating_sub(b.len());
        let to_add = items.len().min(available);
        for item in &items[..to_add] {
            b.push_back(item.clone());
        }
        self.produced_total
            .fetch_add(to_add as u64, Ordering::Relaxed);
        to_add
    }

    /// Consume a single item from the ring.
    pub fn consume(&self) -> Option<T> {
        let mut b = self.buffer.write().unwrap();
        if let Some(item) = b.pop_front() {
            self.consumed_total.fetch_add(1, Ordering::Relaxed);
            Some(item)
        } else {
            None
        }
    }

    /// Consume up to `max` items from the ring.
    pub fn consume_batch(&self, max: usize) -> Vec<T> {
        let mut b = self.buffer.write().unwrap();
        let count = max.min(b.len());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(item) = b.pop_front() {
                out.push(item);
            }
        }
        self.consumed_total
            .fetch_add(count as u64, Ordering::Relaxed);
        out
    }

    /// Current number of items in the ring.
    pub fn len(&self) -> usize {
        self.buffer.read().unwrap().len()
    }

    /// Whether the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Configured ring capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Cumulative items produced.
    pub fn total_produced(&self) -> u64 {
        self.produced_total.load(Ordering::Relaxed)
    }

    /// Cumulative items consumed.
    pub fn total_consumed(&self) -> u64 {
        self.consumed_total.load(Ordering::Relaxed)
    }
}

/// An AF_XDP Queue Pair assigned to a specific hardware NIC RX/TX queue.
pub struct XskQueuePair {
    /// Zero-based queue index (0..=31).
    pub queue_id: u32,
    /// Fill Ring: supplies empty UMEM addresses from userspace to NIC.
    pub fill_ring: XskRing<u64>,
    /// RX Ring: delivers incoming packet descriptors from NIC to userspace.
    pub rx_ring: XskRing<XdpDescriptor>,
    /// TX Ring: submits outbound packet descriptors from userspace to NIC.
    pub tx_ring: XskRing<XdpDescriptor>,
    /// Completion Ring: reclaims completed transmit frame addresses.
    pub completion_ring: XskRing<u64>,
    /// Cumulative RX packets.
    pub rx_packets: AtomicU64,
    /// Cumulative RX bytes.
    pub rx_bytes: AtomicU64,
    /// Cumulative TX packets.
    pub tx_packets: AtomicU64,
    /// Cumulative TX bytes.
    pub tx_bytes: AtomicU64,
    /// Packets dropped due to ring saturation.
    pub ring_drops: AtomicU64,
}

impl XskQueuePair {
    /// Construct a new queue pair with standard ring sizes.
    pub fn new(queue_id: u32, ring_size: usize) -> Self {
        Self {
            queue_id,
            fill_ring: XskRing::new(ring_size),
            rx_ring: XskRing::new(ring_size),
            tx_ring: XskRing::new(ring_size),
            completion_ring: XskRing::new(ring_size),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            ring_drops: AtomicU64::new(0),
        }
    }

    /// Deliver an incoming packet to this queue's RX ring.
    pub fn deliver_rx(&self, desc: XdpDescriptor) -> bool {
        if self.rx_ring.produce(desc) {
            self.rx_packets.fetch_add(1, Ordering::Relaxed);
            self.rx_bytes.fetch_add(desc.len as u64, Ordering::Relaxed);
            true
        } else {
            self.ring_drops.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Pull a batch of received packets from this queue's RX ring.
    pub fn poll_rx(&self, max: usize) -> Vec<XdpDescriptor> {
        self.rx_ring.consume_batch(max)
    }

    /// Submit a packet descriptor to this queue's TX ring.
    pub fn submit_tx(&self, desc: XdpDescriptor) -> bool {
        if self.tx_ring.produce(desc) {
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
            self.tx_bytes.fetch_add(desc.len as u64, Ordering::Relaxed);
            true
        } else {
            self.ring_drops.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Retrieve queue telemetry stats.
    pub fn stats(&self) -> XskQueueStats {
        XskQueueStats {
            queue_id: self.queue_id,
            rx_ring_occupancy: self.rx_ring.len(),
            tx_ring_occupancy: self.tx_ring.len(),
            fill_ring_occupancy: self.fill_ring.len(),
            completion_ring_occupancy: self.completion_ring.len(),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            ring_drops: self.ring_drops.load(Ordering::Relaxed),
        }
    }
}

/// Structured telemetry report for an AF_XDP queue pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XskQueueStats {
    pub queue_id: u32,
    pub rx_ring_occupancy: usize,
    pub tx_ring_occupancy: usize,
    pub fill_ring_occupancy: usize,
    pub completion_ring_occupancy: usize,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub ring_drops: u64,
}
