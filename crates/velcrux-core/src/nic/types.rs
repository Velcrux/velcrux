//! Types, configurations, and packet descriptors for Autonomous Zero-Copy QUIC
//! Kernel-Bypass Direct NIC Memory Fabric (AF_XDP / UMEM) (ADR-083).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Standard XDP packet headroom reserved at the beginning of each UMEM frame (256 bytes).
pub const NIC_DEFAULT_HEADROOM: usize = 256;
/// Default frame size for zero-copy memory buffers (2048 bytes).
pub const NIC_DEFAULT_FRAME_SIZE: usize = 2048;
/// Default total number of frames pre-allocated in UMEM pool (4096 frames = 8 MiB).
pub const NIC_DEFAULT_TOTAL_FRAMES: usize = 4096;
/// Default capacity for SPSC ring buffers (1024 descriptors).
pub const NIC_DEFAULT_RING_SIZE: usize = 1024;

/// Driver operating mode for direct NIC kernel-bypass interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NicDriverMode {
    /// Zero-copy driver mode (`XDP_ZEROCOPY`): hardware NIC DMA directly targets UMEM frame memory.
    ZeroCopyDriver,
    /// Generic copy mode (`XDP_COPY`): kernel fallback copying packet buffer into UMEM frame.
    CopySkbGeneric,
    /// Hardware offload mode (`XDP_FLAGS_HW_MODE`): SmartNIC ASIC / FPGA on-chip packet handling.
    HardwareOffloadAsic,
    /// Cross-platform emulated user-space ring fabric (macOS/BSD/Windows development & testing).
    EmulatedUserSpace,
}

impl NicDriverMode {
    #[must_use]
    pub fn is_zero_copy(&self) -> bool {
        matches!(self, Self::ZeroCopyDriver | Self::HardwareOffloadAsic)
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ZeroCopyDriver => "zero_copy_driver",
            Self::CopySkbGeneric => "copy_skb_generic",
            Self::HardwareOffloadAsic => "hardware_offload_asic",
            Self::EmulatedUserSpace => "emulated_userspace",
        }
    }
}

/// Lifecycle state of an individual UMEM frame buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NicFrameState {
    /// Frame is idle in free stack, available for allocation.
    Free,
    /// Frame address is submitted to Fill Ring, waiting for NIC ingress DMA.
    InFillRing,
    /// Frame contains incoming packet, popped from Rx Ring.
    ReceivedIngress,
    /// Frame is dispatched to active QUIC connection state machine.
    DispatchedToQuic,
    /// Frame contains outgoing packet, submitted to Tx Ring.
    InTxRing,
    /// Frame transmission completed by NIC DMA, waiting in Completion Ring.
    InCompletion,
}

/// Configuration parameters for UMEM memory pool and AF_XDP ring pairs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicUmemConfig {
    /// Size of each frame buffer in bytes (must be power of two, 2048 or 4096).
    pub frame_size: usize,
    /// Total number of frame buffers pre-allocated in the contiguous UMEM pool.
    pub total_frames: usize,
    /// Headroom reserved for packet metadata / driver prefixes (typically 256 bytes).
    pub headroom: usize,
    /// Capacity of Fill Ring (must be power of two).
    pub fill_ring_size: usize,
    /// Capacity of Rx Ring (must be power of two).
    pub rx_ring_size: usize,
    /// Capacity of Tx Ring (must be power of two).
    pub tx_ring_size: usize,
    /// Capacity of Completion Ring (must be power of two).
    pub completion_ring_size: usize,
}

impl Default for NicUmemConfig {
    fn default() -> Self {
        Self {
            frame_size: NIC_DEFAULT_FRAME_SIZE,
            total_frames: NIC_DEFAULT_TOTAL_FRAMES,
            headroom: NIC_DEFAULT_HEADROOM,
            fill_ring_size: NIC_DEFAULT_RING_SIZE,
            rx_ring_size: NIC_DEFAULT_RING_SIZE,
            tx_ring_size: NIC_DEFAULT_RING_SIZE,
            completion_ring_size: NIC_DEFAULT_RING_SIZE,
        }
    }
}

impl NicUmemConfig {
    /// Validate configuration invariants (powers of two and bounds).
    pub fn validate(&self) -> Result<(), NicError> {
        if !self.frame_size.is_power_of_two() || self.frame_size < 1024 {
            return Err(NicError::ConfigError(format!(
                "frame_size ({}) must be a power of two >= 1024",
                self.frame_size
            )));
        }
        if !self.total_frames.is_power_of_two() || self.total_frames < 64 {
            return Err(NicError::ConfigError(format!(
                "total_frames ({}) must be a power of two >= 64",
                self.total_frames
            )));
        }
        if self.headroom >= self.frame_size {
            return Err(NicError::ConfigError(format!(
                "headroom ({}) must be strictly less than frame_size ({})",
                self.headroom, self.frame_size
            )));
        }
        if !self.fill_ring_size.is_power_of_two()
            || !self.rx_ring_size.is_power_of_two()
            || !self.tx_ring_size.is_power_of_two()
            || !self.completion_ring_size.is_power_of_two()
        {
            return Err(NicError::ConfigError(
                "All ring capacities must be powers of two".to_string(),
            ));
        }
        Ok(())
    }
}

/// AF_XDP packet descriptor exchanged between NIC hardware DMA and userspace rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NicPacketDescriptor {
    /// Byte offset within UMEM pool where the packet data begins (addr + headroom).
    pub addr: u64,
    /// Wire length of the packet payload in bytes.
    pub len: u32,
    /// Hardware / driver flags (e.g. `XDP_PKT_CONTD` for jumbo packets).
    pub flags: u32,
}

impl NicPacketDescriptor {
    #[must_use]
    pub fn new(addr: u64, len: u32, flags: u32) -> Self {
        Self { addr, len, flags }
    }
}

/// Parsed QUIC packet classification flags extracted with zero memory allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NicQuicHeaderForm {
    /// QUIC Long Header packet (Initial, 0-RTT, Handshake, Retry).
    LongHeader { packet_type: u8, version: u32 },
    /// QUIC Short Header packet (1-RTT application data protected by AEAD).
    ShortHeader { spin_bit: bool, key_phase: bool },
}

/// Zero-copy parsed view of a QUIC UDP packet directly residing in a UMEM frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicQuicPacketView {
    /// Index of the backing UMEM frame.
    pub frame_index: usize,
    /// Offset within UMEM where L2 Ethernet header begins.
    pub eth_offset: usize,
    /// Offset within UMEM where L3 IP header begins.
    pub ip_offset: usize,
    /// Offset within UMEM where L4 UDP header begins.
    pub udp_offset: usize,
    /// Offset within UMEM where L7 QUIC payload begins.
    pub quic_offset: usize,
    /// Length of QUIC payload in bytes.
    pub quic_len: usize,
    /// Source socket address (IP:port string).
    pub src_addr: String,
    /// Destination socket address (IP:port string).
    pub dst_addr: String,
    /// Destination Connection ID (DCID) bytes as hex string.
    pub dcid_hex: String,
    /// Source Connection ID (SCID) bytes as hex string (if Long Header).
    pub scid_hex: Option<String>,
    /// Header form classification.
    pub header_form: NicQuicHeaderForm,
}

/// Real-time telemetry snapshot of the NIC Memory Fabric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicStatus {
    /// Bound network interface name (e.g. "eth0" or "vlx-nic0").
    pub interface_name: String,
    /// Operating driver mode.
    pub driver_mode: NicDriverMode,
    /// Hardware zero-copy capability active.
    pub zero_copy_active: bool,
    /// Total pre-allocated UMEM memory in bytes.
    pub umem_total_bytes: usize,
    /// Total UMEM frames pre-allocated.
    pub umem_total_frames: usize,
    /// Frames currently allocated or in flight.
    pub frames_in_flight: usize,
    /// Free frames available in UMEM stack.
    pub frames_free: usize,
    /// UMEM frame utilization percentage.
    pub umem_utilization_percent: f64,
    /// Ring occupancy statistics.
    pub fill_ring_count: usize,
    pub rx_ring_count: usize,
    pub tx_ring_count: usize,
    pub completion_ring_count: usize,
    /// Cumulative packet counters.
    pub total_rx_packets: u64,
    pub total_tx_packets: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub dropped_packets: u64,
}

/// Ring occupancy and capacity telemetry report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicRingStats {
    pub ring_name: String,
    pub capacity: usize,
    pub current_len: usize,
    pub total_produced: u64,
    pub total_consumed: u64,
    pub utilization_percent: f64,
}

/// Comprehensive benchmark report evaluating NIC kernel bypass throughput and latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicBenchmarkReport {
    /// Interface evaluated.
    pub interface_name: String,
    /// Total packets processed during benchmark run.
    pub packets_processed: usize,
    /// Frame payload size in bytes.
    pub frame_size_bytes: usize,
    /// Driver mode tested.
    pub driver_mode: NicDriverMode,
    /// Measured throughput in Million Packets Per Second (Mpps).
    pub throughput_mpps: f64,
    /// Measured wire bandwidth in Gigabits per second (Gbps).
    pub throughput_gbps: f64,
    /// Average single-descriptor ring enqueue/dequeue latency in nanoseconds.
    pub ring_cycle_latency_ns: f64,
    /// Zero-copy efficiency percentage (100.0% = zero heap allocations on hot path).
    pub zero_copy_efficiency_percent: f64,
    /// UMEM buffer frame recycling success rate (1.0 = perfect conservation).
    pub frame_reuse_ratio: f64,
}

/// Domain errors encountered during NIC memory fabric operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NicError {
    #[error("Invalid NIC memory fabric configuration: {0}")]
    ConfigError(String),

    #[error("UMEM frame allocation exhausted: 0 of {total} frames available")]
    UmemExhausted { total: usize },

    #[error("UMEM invalid frame access: index {index} out of bounds (max {max})")]
    FrameOutOfBounds { index: usize, max: usize },

    #[error("Ring buffer overflow: {ring} capacity {capacity} exceeded")]
    RingOverflow { ring: String, capacity: usize },

    #[error("Packet parsing error: {0}")]
    ParseError(String),

    #[error("Interface error on {interface}: {message}")]
    InterfaceError { interface: String, message: String },
}

/// Result alias for NIC fabric operations.
pub type NicResult<T> = Result<T, NicError>;
