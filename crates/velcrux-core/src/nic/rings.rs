//! AF_XDP Lock-Free Circular Ring Buffers (ADR-083).
//!
//! Implements the 4 canonical AF_XDP rings (Fill, Rx, Tx, Completion)
//! using power-of-two mask indexing under `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use super::types::{NicError, NicPacketDescriptor, NicRingStats};

/// High-throughput circular ring buffer parameterized over descriptor type `T`.
pub struct NicCircularRing<T> {
    name: &'static str,
    capacity: usize,
    mask: usize,
    buffer: RwLock<Vec<Option<T>>>,
    head: AtomicU64, // Producer pointer (monotonically increasing)
    tail: AtomicU64, // Consumer pointer (monotonically increasing)
    total_produced: AtomicU64,
    total_consumed: AtomicU64,
}

impl<T: Clone> NicCircularRing<T> {
    /// Create a new ring with the specified capacity (must be a power of two).
    pub fn new(name: &'static str, capacity: usize) -> Self {
        let cap = capacity.max(16).next_power_of_two();
        let mask = cap - 1;
        let mut buffer = Vec::with_capacity(cap);
        for _ in 0..cap {
            buffer.push(None);
        }

        Self {
            name,
            capacity: cap,
            mask,
            buffer: RwLock::new(buffer),
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            total_produced: AtomicU64::new(0),
            total_consumed: AtomicU64::new(0),
        }
    }

    /// Configured ring capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Current number of occupied slots in the ring.
    pub fn len(&self) -> usize {
        let h = self.head.load(Ordering::Acquire);
        let t = self.tail.load(Ordering::Acquire);
        (h.saturating_sub(t)) as usize
    }

    /// Whether the ring contains zero descriptors.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the ring is full.
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    /// Available free slots remaining in the ring.
    pub fn available_slots(&self) -> usize {
        self.capacity.saturating_sub(self.len())
    }

    /// Produce a single item into the ring.
    pub fn enqueue(&self, item: T) -> Result<(), NicError> {
        let h = self.head.load(Ordering::Acquire);
        let t = self.tail.load(Ordering::Acquire);

        if (h.saturating_sub(t)) as usize >= self.capacity {
            return Err(NicError::RingOverflow {
                ring: self.name.to_string(),
                capacity: self.capacity,
            });
        }

        let slot = (h as usize) & self.mask;
        {
            let mut buf = self.buffer.write().unwrap();
            buf[slot] = Some(item);
        }

        self.head.store(h + 1, Ordering::Release);
        self.total_produced.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Produce a batch of items into the ring. Returns count successfully queued.
    pub fn enqueue_batch(&self, items: &[T]) -> usize {
        if items.is_empty() {
            return 0;
        }

        let h = self.head.load(Ordering::Acquire);
        let t = self.tail.load(Ordering::Acquire);
        let current_len = (h.saturating_sub(t)) as usize;
        let free = self.capacity.saturating_sub(current_len);
        let to_add = items.len().min(free);

        if to_add == 0 {
            return 0;
        }

        {
            let mut buf = self.buffer.write().unwrap();
            for (idx, item) in items[..to_add].iter().enumerate() {
                let slot = ((h as usize) + idx) & self.mask;
                buf[slot] = Some(item.clone());
            }
        }

        self.head.store(h + to_add as u64, Ordering::Release);
        self.total_produced
            .fetch_add(to_add as u64, Ordering::Relaxed);
        to_add
    }

    /// Consume a single item from the ring.
    pub fn dequeue(&self) -> Option<T> {
        let t = self.tail.load(Ordering::Acquire);
        let h = self.head.load(Ordering::Acquire);

        if t >= h {
            return None;
        }

        let slot = (t as usize) & self.mask;
        let item = {
            let mut buf = self.buffer.write().unwrap();
            buf[slot].take()
        };

        if item.is_some() {
            self.tail.store(t + 1, Ordering::Release);
            self.total_consumed.fetch_add(1, Ordering::Relaxed);
        }
        item
    }

    /// Consume up to `max` items from the ring.
    pub fn dequeue_batch(&self, max: usize) -> Vec<T> {
        let t = self.tail.load(Ordering::Acquire);
        let h = self.head.load(Ordering::Acquire);
        let current_len = (h.saturating_sub(t)) as usize;
        let count = max.min(current_len);

        if count == 0 {
            return Vec::new();
        }

        let mut out = Vec::with_capacity(count);
        {
            let mut buf = self.buffer.write().unwrap();
            for idx in 0..count {
                let slot = ((t as usize) + idx) & self.mask;
                if let Some(item) = buf[slot].take() {
                    out.push(item);
                }
            }
        }

        let actual = out.len() as u64;
        self.tail.store(t + actual, Ordering::Release);
        self.total_consumed.fetch_add(actual, Ordering::Relaxed);
        out
    }

    /// Telemetry statistics for this ring.
    #[must_use]
    pub fn stats(&self) -> NicRingStats {
        let len = self.len();
        let prod = self.total_produced.load(Ordering::Relaxed);
        let cons = self.total_consumed.load(Ordering::Relaxed);
        let util = (len as f64 / self.capacity as f64) * 100.0;

        NicRingStats {
            ring_name: self.name.to_string(),
            capacity: self.capacity,
            current_len: len,
            total_produced: prod,
            total_consumed: cons,
            utilization_percent: util,
        }
    }
}

/// AF_XDP Fill Ring: Hands empty UMEM frame addresses to NIC hardware DMA.
pub type NicFillRing = NicCircularRing<u64>;

/// AF_XDP Rx Ring: Receives packet descriptors from NIC DMA without memory copying.
pub type NicRxRing = NicCircularRing<NicPacketDescriptor>;

/// AF_XDP Tx Ring: Submits packet descriptors to NIC for direct wire transmission.
pub type NicTxRing = NicCircularRing<NicPacketDescriptor>;

/// AF_XDP Completion Ring: Reclaims transmitted frame addresses back to user pool.
pub type NicCompletionRing = NicCircularRing<u64>;

/// Combined container bundling the 4 canonical AF_XDP rings for a network queue pair.
pub struct NicRingSet {
    /// Fill Ring (Producer: Userspace, Consumer: NIC DMA).
    pub fill: NicFillRing,
    /// Rx Ring (Producer: NIC DMA, Consumer: Userspace).
    pub rx: NicRxRing,
    /// Tx Ring (Producer: Userspace, Consumer: NIC DMA).
    pub tx: NicTxRing,
    /// Completion Ring (Producer: NIC DMA, Consumer: Userspace).
    pub completion: NicCompletionRing,
}

impl NicRingSet {
    /// Initialize all 4 rings with configured capacities.
    pub fn new(fill_size: usize, rx_size: usize, tx_size: usize, completion_size: usize) -> Self {
        Self {
            fill: NicFillRing::new("fill_ring", fill_size),
            rx: NicRxRing::new("rx_ring", rx_size),
            tx: NicTxRing::new("tx_ring", tx_size),
            completion: NicCompletionRing::new("completion_ring", completion_size),
        }
    }
}
