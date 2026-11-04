//! AF_XDP Multi-Queue Flow Steering & XSKMAP Architecture (`ADR-066`).
//!
//! Directs incoming QUIC UDP packets across multiple AF_XDP socket queues
//! pinned to specific CPU worker threads using:
//! - QUIC Connection ID (DCID) consistent hashing
//! - Symmetric 4-tuple RSS hashing
//! - Round-robin queue allocation
//! - Dynamic BPF XSKMAP registration

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::xdp::parser::DissectedPacket;
use crate::xdp::ring::{XskQueuePair, XskQueueStats};
use crate::xdp::{UmemPool, XdpAction, XdpDescriptor};

/// Flow steering policy used by the XDP router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SteeringPolicy {
    /// Route packets based on consistent hash of the QUIC Destination Connection ID (DCID).
    /// Guarantees that all packets for a QUIC connection arrive at the same CPU core.
    CidHash,
    /// Symmetric 4-tuple hash (src_ip, dst_ip, src_port, dst_port) ensuring bidirectional symmetry.
    Symmetric4Tuple,
    /// Round-robin distribution across active queue pairs.
    RoundRobin,
    /// Pin all accelerated traffic to a specific hardware queue ID.
    PinToQueue(u32),
}

/// BPF XSKMAP representation maintaining active AF_XDP queue sockets.
pub struct XskMap {
    queues: RwLock<HashMap<u32, Arc<XskQueuePair>>>,
    num_queues: AtomicU32,
}

impl XskMap {
    /// Create a new XSKMAP with $N$ pre-allocated queue pairs.
    pub fn new(num_queues: u32, ring_size: usize) -> Self {
        let mut map = HashMap::new();
        for q in 0..num_queues {
            map.insert(q, Arc::new(XskQueuePair::new(q, ring_size)));
        }

        Self {
            queues: RwLock::new(map),
            num_queues: AtomicU32::new(num_queues),
        }
    }

    /// Retrieve queue pair by ID.
    pub fn get_queue(&self, queue_id: u32) -> Option<Arc<XskQueuePair>> {
        self.queues.read().unwrap().get(&queue_id).cloned()
    }

    /// Register a new queue pair.
    pub fn register_queue(&self, queue: Arc<XskQueuePair>) {
        let qid = queue.queue_id;
        let mut map = self.queues.write().unwrap();
        map.insert(qid, queue);
        self.num_queues.store(map.len() as u32, Ordering::Relaxed);
    }

    /// Number of registered queues.
    pub fn queue_count(&self) -> u32 {
        self.num_queues.load(Ordering::Relaxed)
    }

    /// Retrieve stats across all registered queues.
    pub fn all_queue_stats(&self) -> Vec<XskQueueStats> {
        let map = self.queues.read().unwrap();
        let mut out = Vec::with_capacity(map.len());
        for q in map.values() {
            out.push(q.stats());
        }
        out.sort_by_key(|s| s.queue_id);
        out
    }
}

/// Multi-queue router executing packet steering policies.
pub struct XdpSocketRouter {
    policy: SteeringPolicy,
    xsk_map: Arc<XskMap>,
    umem: Arc<UmemPool>,
    rr_counter: AtomicU32,
    packets_steered: AtomicU64,
    packets_dropped: AtomicU64,
    packets_passed: AtomicU64,
}

impl XdpSocketRouter {
    /// Construct a new router with the specified steering policy and XSKMAP.
    pub fn new(policy: SteeringPolicy, xsk_map: Arc<XskMap>, umem: Arc<UmemPool>) -> Self {
        Self {
            policy,
            xsk_map,
            umem,
            rr_counter: AtomicU32::new(0),
            packets_steered: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_passed: AtomicU64::new(0),
        }
    }

    /// Route an incoming dissected packet to the appropriate AF_XDP queue.
    pub fn steer_packet(
        &self,
        packet: &DissectedPacket,
        target_port: u16,
    ) -> Result<(XdpAction, Option<u32>), VelcruxError> {
        // Only steer UDP packets destined for the target port
        if packet.dst_port != target_port {
            self.packets_passed.fetch_add(1, Ordering::Relaxed);
            return Ok((XdpAction::Pass, None));
        }

        let num_queues = self.xsk_map.queue_count();
        if num_queues == 0 {
            self.packets_passed.fetch_add(1, Ordering::Relaxed);
            return Ok((XdpAction::Pass, None));
        }

        // Calculate target queue based on steering policy
        let target_queue = match self.policy {
            SteeringPolicy::PinToQueue(qid) => qid % num_queues,
            SteeringPolicy::RoundRobin => {
                let count = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                count % num_queues
            }
            SteeringPolicy::CidHash => {
                if let Some(ref cid) = packet.quic_dcid_bytes {
                    let hash = compute_hash(cid);
                    (hash % (num_queues as u64)) as u32
                } else {
                    // Fall back to 4-tuple if no CID present
                    compute_4tuple_hash(packet) % num_queues
                }
            }
            SteeringPolicy::Symmetric4Tuple => compute_4tuple_hash(packet) % num_queues,
        };

        // Allocate UMEM frame and deliver to queue RX ring
        if let Some(queue) = self.xsk_map.get_queue(target_queue) {
            if let Some(addr) = self.umem.alloc_frame() {
                let desc = XdpDescriptor {
                    addr,
                    len: packet.total_frame_len as u32,
                    flags: 0,
                };
                if queue.deliver_rx(desc) {
                    self.packets_steered.fetch_add(1, Ordering::Relaxed);
                    return Ok((XdpAction::Redirect, Some(target_queue)));
                } else {
                    // Ring full: free allocated frame and drop
                    self.umem.free_frame(addr);
                    self.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok((XdpAction::Drop, Some(target_queue)));
                }
            } else {
                // Out of UMEM frames
                self.packets_dropped.fetch_add(1, Ordering::Relaxed);
                return Ok((XdpAction::Drop, Some(target_queue)));
            }
        }

        self.packets_passed.fetch_add(1, Ordering::Relaxed);
        Ok((XdpAction::Pass, None))
    }

    /// Retrieve active steering report.
    pub fn report(&self) -> SteeringReport {
        let queue_stats = self.xsk_map.all_queue_stats();
        let total_steered = self.packets_steered.load(Ordering::Relaxed);

        SteeringReport {
            policy: self.policy,
            num_queues: self.xsk_map.queue_count(),
            total_steered,
            total_dropped: self.packets_dropped.load(Ordering::Relaxed),
            total_passed: self.packets_passed.load(Ordering::Relaxed),
            queues: queue_stats,
        }
    }
}

/// Telemetry summary report for flow steering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteeringReport {
    pub policy: SteeringPolicy,
    pub num_queues: u32,
    pub total_steered: u64,
    pub total_dropped: u64,
    pub total_passed: u64,
    pub queues: Vec<XskQueueStats>,
}

fn compute_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn compute_4tuple_hash(packet: &DissectedPacket) -> u32 {
    let mut h = compute_hash(packet.src_ip.as_bytes()) ^ compute_hash(packet.dst_ip.as_bytes());
    let ports = ((packet.src_port as u32) << 16) | (packet.dst_port as u32);
    h ^= ports as u64;
    (h & 0xFFFFFFFF) as u32
}
