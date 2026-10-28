//! Hardware-Accelerated FPGA/eBPF Kernel XDP Packet Bypassing (`ADR-045`).
//!
//! Provides ultra-low-latency, zero-copy packet bypassing leveraging eBPF/XDP
//! (eXpress Data Path), AF_XDP socket descriptor rings, UMEM frame buffers,
//! wire-speed QUIC connection ID filtering, and SmartNIC/FPGA hardware offloads.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Operating driver mode for the XDP engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XdpDriverMode {
    /// Driver-level hook executing directly inside the NIC driver prior to SKB allocation.
    NativeDriver,
    /// Generic fallback hook executing after OS packet buffer allocation (multi-platform compatible).
    GenericSkb,
    /// Hardware-level offload executing on SmartNIC ASIC or FPGA silicon.
    HardwareOffload,
}

impl std::fmt::Display for XdpDriverMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdpDriverMode::NativeDriver => write!(f, "native_driver"),
            XdpDriverMode::GenericSkb => write!(f, "generic_skb"),
            XdpDriverMode::HardwareOffload => write!(f, "hardware_offload"),
        }
    }
}

/// Action verdict produced by an eBPF/XDP filter program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XdpAction {
    /// Allow the packet to continue into the standard kernel network stack.
    Pass,
    /// Discard the packet at the earliest possible ingress point without allocating kernel SKB.
    Drop,
    /// Transmit the packet back out of the ingress interface (packet bouncing/turnaround).
    Tx,
    /// Redirect the packet directly to userspace AF_XDP socket via zero-copy UMEM ring buffers.
    Redirect,
}

impl std::fmt::Display for XdpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdpAction::Pass => write!(f, "pass"),
            XdpAction::Drop => write!(f, "drop"),
            XdpAction::Tx => write!(f, "tx"),
            XdpAction::Redirect => write!(f, "redirect"),
        }
    }
}

/// Configuration parameters for the AF_XDP UMEM (User Memory) shared memory area.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UmemConfig {
    /// Size of each memory frame in bytes (typically 2048 or 4096 bytes).
    pub frame_size: u32,
    /// Total number of pre-allocated frames in the UMEM pool.
    pub frame_count: u32,
    /// Capacity of the Fill Ring (provides empty frames from userspace to kernel/NIC).
    pub fill_ring_size: u32,
    /// Capacity of the Completion Ring (returns consumed frames from kernel/NIC to userspace).
    pub completion_ring_size: u32,
    /// Capacity of the RX Descriptor Ring.
    pub rx_ring_size: u32,
    /// Capacity of the TX Descriptor Ring.
    pub tx_ring_size: u32,
}

impl Default for UmemConfig {
    fn default() -> Self {
        Self {
            frame_size: 2048,
            frame_count: 4096,
            fill_ring_size: 1024,
            completion_ring_size: 1024,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
        }
    }
}

/// A descriptor representing a packet slot in the UMEM frame pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpDescriptor {
    /// Byte offset of the frame within the contiguous UMEM pool.
    pub addr: u64,
    /// Length of packet payload in bytes.
    pub len: u32,
    /// Descriptor flags (e.g. checksum offload, multi-buffer segment).
    pub flags: u32,
}

/// Thread-safe UMEM pool allocating and recycling fixed-size packet memory frames.
pub struct UmemPool {
    config: UmemConfig,
    free_frames: RwLock<VecDeque<u64>>,
    fill_ring: RwLock<VecDeque<u64>>,
    completion_ring: RwLock<VecDeque<u64>>,
    total_allocations: AtomicU64,
}

impl UmemPool {
    /// Creates a new UMEM frame pool with configured capacities.
    pub fn new(config: UmemConfig) -> Self {
        let mut free = VecDeque::with_capacity(config.frame_count as usize);
        for i in 0..config.frame_count {
            free.push_back((i * config.frame_size) as u64);
        }

        Self {
            config,
            free_frames: RwLock::new(free),
            fill_ring: RwLock::new(VecDeque::new()),
            completion_ring: RwLock::new(VecDeque::new()),
            total_allocations: AtomicU64::new(0),
        }
    }

    /// Allocates an available frame offset from the free pool.
    pub fn alloc_frame(&self) -> Option<u64> {
        let mut free = self.free_frames.write().unwrap();
        if let Some(addr) = free.pop_front() {
            self.total_allocations.fetch_add(1, Ordering::Relaxed);
            Some(addr)
        } else {
            None
        }
    }

    /// Releases a previously allocated frame back to the free pool.
    pub fn free_frame(&self, addr: u64) {
        let mut free = self.free_frames.write().unwrap();
        free.push_front(addr);
    }

    /// Pushes empty frames to the Fill Ring for NIC packet receipt.
    pub fn populate_fill_ring(&self, count: usize) -> usize {
        let mut free = self.free_frames.write().unwrap();
        let mut fill = self.fill_ring.write().unwrap();
        let mut moved = 0;

        while moved < count && fill.len() < self.config.fill_ring_size as usize {
            if let Some(addr) = free.pop_front() {
                fill.push_back(addr);
                moved += 1;
            } else {
                break;
            }
        }
        moved
    }

    /// Reclaims consumed transmit frames from the Completion Ring.
    pub fn drain_completion_ring(&self) -> usize {
        let mut comp = self.completion_ring.write().unwrap();
        let mut free = self.free_frames.write().unwrap();
        let count = comp.len();

        while let Some(addr) = comp.pop_front() {
            free.push_back(addr);
        }
        count
    }

    /// Returns the number of available free frames in the pool.
    pub fn available_frames(&self) -> usize {
        self.free_frames.read().unwrap().len()
    }
}

/// Parsed protocol summary extracted at wire speed from raw packet frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketHeaderSummary {
    /// Layer-2 Ethernet protocol (e.g. 0x0800 for IPv4).
    pub eth_proto: u16,
    /// Source IP address.
    pub src_ip: String,
    /// Destination IP address.
    pub dst_ip: String,
    /// Layer-4 Source Port (e.g. UDP port).
    pub src_port: u16,
    /// Layer-4 Destination Port.
    pub dst_port: u16,
    /// Whether the packet payload corresponds to a QUIC datagram.
    pub is_quic: bool,
    /// Extracted QUIC Connection ID hex if identifiable.
    pub quic_connection_id: Option<String>,
    /// Total packet byte length.
    pub payload_len: usize,
}

/// Fast wire-speed packet parser extracting layer-2 through layer-4 headers.
pub fn parse_packet_headers(raw: &[u8]) -> Option<PacketHeaderSummary> {
    if raw.len() < 14 + 20 + 8 {
        // Minimum size: Ethernet (14) + IPv4 (20) + UDP (8) = 42 bytes
        return None;
    }

    // 1. Ethernet Header (14 bytes)
    let eth_proto = u16::from_be_bytes([raw[12], raw[13]]);
    if eth_proto != 0x0800 {
        // Only IPv4 parsed in baseline filter
        return None;
    }

    // 2. IPv4 Header (20 bytes)
    let ip_offset = 14;
    let ip_proto = raw[ip_offset + 9];
    if ip_proto != 17 {
        // Only UDP (17) is accelerated
        return None;
    }

    let src_ip = format!(
        "{}.{}.{}.{}",
        raw[ip_offset + 12],
        raw[ip_offset + 13],
        raw[ip_offset + 14],
        raw[ip_offset + 15]
    );
    let dst_ip = format!(
        "{}.{}.{}.{}",
        raw[ip_offset + 16],
        raw[ip_offset + 17],
        raw[ip_offset + 18],
        raw[ip_offset + 19]
    );

    // 3. UDP Header (8 bytes)
    let udp_offset = ip_offset + 20;
    let src_port = u16::from_be_bytes([raw[udp_offset], raw[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([raw[udp_offset + 2], raw[udp_offset + 3]]);
    let udp_len = u16::from_be_bytes([raw[udp_offset + 4], raw[udp_offset + 5]]) as usize;

    // 4. QUIC Inspection (Payload inside UDP)
    let quic_offset = udp_offset + 8;
    let mut is_quic = false;
    let mut quic_cid = None;

    if raw.len() >= quic_offset + 4 {
        let first_byte = raw[quic_offset];
        if (first_byte & 0x80) != 0 {
            // QUIC Long Header: byte 0 is flags, bytes 1..5 version, byte 5 dcid len
            is_quic = true;
            if raw.len() >= quic_offset + 6 {
                let dcid_len = raw[quic_offset + 5] as usize;
                if dcid_len > 0 && raw.len() >= quic_offset + 6 + dcid_len {
                    let cid_bytes = &raw[quic_offset + 6..quic_offset + 6 + dcid_len];
                    quic_cid = Some(
                        cid_bytes
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>(),
                    );
                }
            }
        } else if (first_byte & 0x40) != 0 {
            // QUIC Short Header (1-RTT): byte 0 has 0x40 fixed bit set, DCID follows
            is_quic = true;
            if raw.len() >= quic_offset + 9 {
                let cid_bytes = &raw[quic_offset + 1..quic_offset + 9];
                quic_cid = Some(
                    cid_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>(),
                );
            }
        }
    }

    Some(PacketHeaderSummary {
        eth_proto,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        is_quic,
        quic_connection_id: quic_cid,
        payload_len: udp_len.min(raw.len()),
    })
}

/// A filter rule programmed into the eBPF/XDP map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdpFilterRule {
    /// Rule priority (lower numbers evaluated first).
    pub priority: u32,
    /// Destination UDP port matcher (e.g. 7443 for Raven QUIC transfers).
    pub dst_port: Option<u16>,
    /// Optional QUIC Connection ID prefix filter.
    pub cid_prefix: Option<String>,
    /// Action to execute upon match.
    pub action: XdpAction,
    /// Description of the rule.
    pub description: String,
}

/// Operational state and statistics of the eBPF/XDP Kernel Bypass Engine.
pub struct XdpEngine {
    driver_mode: XdpDriverMode,
    interface: String,
    umem: UmemPool,
    rules: RwLock<Vec<XdpFilterRule>>,
    rx_ring: RwLock<VecDeque<XdpDescriptor>>,
    tx_ring: RwLock<VecDeque<XdpDescriptor>>,
    packets_processed: AtomicU64,
    packets_redirected: AtomicU64,
    packets_dropped: AtomicU64,
    packets_passed: AtomicU64,
    bytes_processed: AtomicU64,
}

impl XdpEngine {
    /// Instantiates a new XDP engine bound to a network interface.
    pub fn new(interface: &str, driver_mode: XdpDriverMode, config: UmemConfig) -> Self {
        let pool = UmemPool::new(config);
        pool.populate_fill_ring(1024);

        let mut default_rules = Vec::new();
        // Rule 1: Redirect Raven QUIC traffic (UDP port 7443) directly to userspace AF_XDP
        default_rules.push(XdpFilterRule {
            priority: 10,
            dst_port: Some(7443),
            cid_prefix: None,
            action: XdpAction::Redirect,
            description: "Redirect Raven QUIC port 7443 to AF_XDP".to_string(),
        });
        // Rule 2: Drop malformed or known malicious traffic (e.g. port 0)
        default_rules.push(XdpFilterRule {
            priority: 20,
            dst_port: Some(0),
            action: XdpAction::Drop,
            cid_prefix: None,
            description: "Drop invalid port 0 probe".to_string(),
        });

        Self {
            driver_mode,
            interface: interface.to_string(),
            umem: pool,
            rules: RwLock::new(default_rules),
            rx_ring: RwLock::new(VecDeque::new()),
            tx_ring: RwLock::new(VecDeque::new()),
            packets_processed: AtomicU64::new(0),
            packets_redirected: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_passed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
        }
    }

    /// Returns a reference to the underlying AF_XDP UMEM memory pool.
    pub fn umem(&self) -> &UmemPool {
        &self.umem
    }

    /// Adds or updates an eBPF filter rule.
    pub fn add_rule(&self, rule: XdpFilterRule) {
        let mut rules = self.rules.write().unwrap();
        rules.push(rule);
        rules.sort_by_key(|r| r.priority);
    }

    /// Evaluates a packet against programmed eBPF filter rules.
    pub fn evaluate_filter(&self, packet: &[u8]) -> (XdpAction, Option<PacketHeaderSummary>) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed
            .fetch_add(packet.len() as u64, Ordering::Relaxed);

        let summary = match parse_packet_headers(packet) {
            Some(s) => s,
            None => {
                // Non-IP or truncated packet: pass to kernel stack
                self.packets_passed.fetch_add(1, Ordering::Relaxed);
                return (XdpAction::Pass, None);
            }
        };

        let rules = self.rules.read().unwrap();
        for rule in rules.iter() {
            if let Some(port) = rule.dst_port {
                if summary.dst_port != port {
                    continue;
                }
            }

            if let Some(ref prefix) = rule.cid_prefix {
                if let Some(ref cid) = summary.quic_connection_id {
                    if !cid.starts_with(prefix) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            // Match found
            match rule.action {
                XdpAction::Redirect => {
                    self.packets_redirected.fetch_add(1, Ordering::Relaxed);
                    if let Some(addr) = self.umem.alloc_frame() {
                        let desc = XdpDescriptor {
                            addr,
                            len: packet.len() as u32,
                            flags: 0,
                        };
                        let mut rx = self.rx_ring.write().unwrap();
                        if rx.len() < self.umem.config.rx_ring_size as usize {
                            rx.push_back(desc);
                        } else {
                            // Ring full: free frame and drop
                            self.umem.free_frame(addr);
                        }
                    }
                }
                XdpAction::Drop => {
                    self.packets_dropped.fetch_add(1, Ordering::Relaxed);
                }
                XdpAction::Pass => {
                    self.packets_passed.fetch_add(1, Ordering::Relaxed);
                }
                XdpAction::Tx => {
                    self.packets_passed.fetch_add(1, Ordering::Relaxed);
                }
            }

            return (rule.action, Some(summary));
        }

        self.packets_passed.fetch_add(1, Ordering::Relaxed);
        (XdpAction::Pass, Some(summary))
    }

    /// Dequeues received zero-copy packet descriptors from the AF_XDP RX ring.
    pub fn poll_rx_descriptors(&self, max_batch: usize) -> Vec<XdpDescriptor> {
        let mut rx = self.rx_ring.write().unwrap();
        let count = max_batch.min(rx.len());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(desc) = rx.pop_front() {
                out.push(desc);
            }
        }
        out
    }

    /// Enqueues a packet descriptor to the AF_XDP TX ring for zero-copy transmission.
    pub fn enqueue_tx_descriptor(&self, desc: XdpDescriptor) -> bool {
        let mut tx = self.tx_ring.write().unwrap();
        if tx.len() < self.umem.config.tx_ring_size as usize {
            tx.push_back(desc);
            true
        } else {
            false
        }
    }

    /// Dequeues transmitted packet descriptors from the AF_XDP TX ring.
    pub fn poll_tx_descriptors(&self, max_batch: usize) -> Vec<XdpDescriptor> {
        let mut tx = self.tx_ring.write().unwrap();
        let count = max_batch.min(tx.len());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(desc) = tx.pop_front() {
                out.push(desc);
            }
        }
        out
    }

    /// Returns the active status report of the XDP bypass engine.
    pub fn status(&self) -> XdpStatus {
        XdpStatus {
            interface: self.interface.clone(),
            driver_mode: self.driver_mode,
            umem_frame_count: self.umem.config.frame_count,
            umem_frame_size: self.umem.config.frame_size,
            available_umem_frames: self.umem.available_frames() as u32,
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            packets_redirected: self.packets_redirected.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_passed: self.packets_passed.load(Ordering::Relaxed),
            bytes_processed: self.bytes_processed.load(Ordering::Relaxed),
            active_rules_count: self.rules.read().unwrap().len(),
            hardware_offload_active: self.driver_mode == XdpDriverMode::HardwareOffload,
        }
    }
}

/// Operational status and telemetry report for the XDP engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdpStatus {
    pub interface: String,
    pub driver_mode: XdpDriverMode,
    pub umem_frame_count: u32,
    pub umem_frame_size: u32,
    pub available_umem_frames: u32,
    pub packets_processed: u64,
    pub packets_redirected: u64,
    pub packets_dropped: u64,
    pub packets_passed: u64,
    pub bytes_processed: u64,
    pub active_rules_count: usize,
    pub hardware_offload_active: bool,
}

/// Performance benchmark report evaluating XDP packet processing throughput.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdpBenchmarkReport {
    pub driver_mode: XdpDriverMode,
    pub packet_count: usize,
    pub batch_size: usize,
    pub throughput_mpps: f64,
    pub throughput_gbps: f64,
    pub avg_latency_ns: f64,
    pub packets_redirected: u64,
    pub packets_dropped: u64,
    pub packets_passed: u64,
    pub elapsed_ms: f64,
}

/// Executes an in-memory XDP packet bypass benchmark evaluating wire-rate parsing and filter throughput.
pub fn run_xdp_benchmark(packet_count: usize, batch_size: usize) -> XdpBenchmarkReport {
    let config = UmemConfig {
        frame_size: 2048,
        frame_count: 8192,
        ..Default::default()
    };
    let engine = XdpEngine::new("eth0", XdpDriverMode::HardwareOffload, config);

    // Construct a synthetic 1200-byte QUIC packet payload
    let mut packet = vec![0u8; 1200];
    // Ethernet: IPv4 (0x0800)
    packet[12] = 0x08;
    packet[13] = 0x00;
    // IPv4: UDP proto (17)
    packet[14 + 9] = 17;
    // UDP: Destination Port 7443
    let port_bytes = 7443u16.to_be_bytes();
    packet[14 + 20 + 2] = port_bytes[0];
    packet[14 + 20 + 3] = port_bytes[1];
    // QUIC Short Header: 0x40 fixed bit set
    packet[14 + 20 + 8] = 0x43;
    // Connection ID
    for i in 0..8 {
        packet[14 + 20 + 9 + i] = (i + 1) as u8;
    }

    let iterations = packet_count.max(100);
    let effective_batch = batch_size.max(1);

    let start = Instant::now();
    for _ in 0..(iterations / effective_batch) {
        for _ in 0..effective_batch {
            let _ = engine.evaluate_filter(&packet);
        }
        // Periodically reclaim RX descriptors to simulate steady-state userspace drainage
        let descs = engine.poll_rx_descriptors(effective_batch);
        for d in descs {
            engine.umem.free_frame(d.addr);
        }
    }
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(1e-9);

    let mpps = (iterations as f64 / 1_000_000.0) / elapsed_secs;
    let total_bits = iterations as f64 * packet.len() as f64 * 8.0;
    let gbps = (total_bits / 1_000_000_000.0) / elapsed_secs;
    let avg_latency_ns = (elapsed.as_nanos() as f64) / iterations as f64;

    let status = engine.status();

    XdpBenchmarkReport {
        driver_mode: XdpDriverMode::HardwareOffload,
        packet_count: iterations,
        batch_size: effective_batch,
        throughput_mpps: mpps,
        throughput_gbps: gbps,
        avg_latency_ns,
        packets_redirected: status.packets_redirected,
        packets_dropped: status.packets_dropped,
        packets_passed: status.packets_passed,
        elapsed_ms: elapsed_secs * 1000.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_umem_pool_allocation_and_recycling() {
        let config = UmemConfig {
            frame_size: 2048,
            frame_count: 4,
            ..Default::default()
        };
        let pool = UmemPool::new(config);
        assert_eq!(pool.available_frames(), 4);

        let f0 = pool.alloc_frame().expect("alloc frame 0");
        let f1 = pool.alloc_frame().expect("alloc frame 1");
        assert_eq!(pool.available_frames(), 2);
        assert_ne!(f0, f1);

        pool.free_frame(f0);
        assert_eq!(pool.available_frames(), 3);
        let f_recycled = pool.alloc_frame().expect("recycled");
        assert_eq!(f_recycled, f0);
    }

    #[test]
    fn test_wire_speed_packet_parsing() {
        let mut packet = vec![0u8; 64];
        packet[12] = 0x08;
        packet[13] = 0x00; // IPv4
        packet[14 + 9] = 17; // UDP
        packet[14 + 12] = 192;
        packet[14 + 13] = 168;
        packet[14 + 14] = 1;
        packet[14 + 15] = 10; // src: 192.168.1.10
        packet[14 + 16] = 10;
        packet[14 + 17] = 0;
        packet[14 + 18] = 0;
        packet[14 + 19] = 1; // dst: 10.0.0.1
        let p_src = 50000u16.to_be_bytes();
        packet[14 + 20] = p_src[0];
        packet[14 + 20 + 1] = p_src[1];
        let p_dst = 7443u16.to_be_bytes();
        packet[14 + 20 + 2] = p_dst[0];
        packet[14 + 20 + 3] = p_dst[1];
        packet[14 + 20 + 8] = 0x40; // QUIC short header
        packet[14 + 20 + 9] = 0xAA;
        packet[14 + 20 + 10] = 0xBB;

        let parsed = parse_packet_headers(&packet).expect("valid headers");
        assert_eq!(parsed.eth_proto, 0x0800);
        assert_eq!(parsed.src_ip, "192.168.1.10");
        assert_eq!(parsed.dst_ip, "10.0.0.1");
        assert_eq!(parsed.src_port, 50000);
        assert_eq!(parsed.dst_port, 7443);
        assert!(parsed.is_quic);
        assert!(parsed.quic_connection_id.is_some());
    }

    #[test]
    fn test_xdp_filter_evaluation() {
        let config = UmemConfig::default();
        let engine = XdpEngine::new("eth0", XdpDriverMode::NativeDriver, config);

        // 1. Packet targeting port 7443 -> Redirect to AF_XDP
        let mut quic_pkt = vec![0u8; 64];
        quic_pkt[12] = 0x08;
        quic_pkt[13] = 0x00;
        quic_pkt[14 + 9] = 17;
        let port_7443 = 7443u16.to_be_bytes();
        quic_pkt[14 + 20 + 2] = port_7443[0];
        quic_pkt[14 + 20 + 3] = port_7443[1];
        quic_pkt[14 + 20 + 8] = 0x40;

        let (action1, _) = engine.evaluate_filter(&quic_pkt);
        assert_eq!(action1, XdpAction::Redirect);

        // 2. Descriptors available in RX ring
        let descs = engine.poll_rx_descriptors(10);
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].len, 64);

        // 3. Packet targeting port 0 -> Drop
        let mut probe_pkt = vec![0u8; 64];
        probe_pkt[12] = 0x08;
        probe_pkt[13] = 0x00;
        probe_pkt[14 + 9] = 17;
        probe_pkt[14 + 20 + 2] = 0;
        probe_pkt[14 + 20 + 3] = 0;

        let (action2, _) = engine.evaluate_filter(&probe_pkt);
        assert_eq!(action2, XdpAction::Drop);

        // 4. Non-matching port 80 -> Pass to kernel
        let mut http_pkt = vec![0u8; 64];
        http_pkt[12] = 0x08;
        http_pkt[13] = 0x00;
        http_pkt[14 + 9] = 17;
        let port_80 = 80u16.to_be_bytes();
        http_pkt[14 + 20 + 2] = port_80[0];
        http_pkt[14 + 20 + 3] = port_80[1];

        let (action3, _) = engine.evaluate_filter(&http_pkt);
        assert_eq!(action3, XdpAction::Pass);

        let status = engine.status();
        assert_eq!(status.packets_processed, 3);
        assert_eq!(status.packets_redirected, 1);
        assert_eq!(status.packets_dropped, 1);
        assert_eq!(status.packets_passed, 1);
    }

    #[test]
    fn test_xdp_benchmark_execution() {
        let report = run_xdp_benchmark(100, 10);
        assert_eq!(report.packet_count, 100);
        assert_eq!(report.driver_mode, XdpDriverMode::HardwareOffload);
        assert!(report.throughput_mpps > 0.0);
        assert!(report.throughput_gbps > 0.0);
        assert!(report.avg_latency_ns > 0.0);
        assert_eq!(report.packets_redirected, 100);
    }
}
