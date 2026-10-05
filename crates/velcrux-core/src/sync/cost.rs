//! Adaptive Cost Estimator & Network-Aware Automatic Mode Selection (`REQUIREMENTS.md` §55, §88, `OPERATIONS.md` §12).
//!
//! Provides empirical cost modeling comparing Direct Streaming vs Delta CDC Reconstruction
//! based on real-time network parameters (bandwidth, RTT, loss) and local/remote device profiles (disk I/O, hash speed).

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::transport::stats::TransportStats;

/// Recommended or configured transfer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferMode {
    /// Automatically determine the most efficient mode using the adaptive cost model.
    Auto,
    /// Direct stream transfer: bypasses delta negotiation and staging reconstruction.
    DirectStream,
    /// Delta CDC transfer: uses FastCDC content-defined chunking to negotiate and transfer only diffs.
    DeltaCDC,
    /// Delta fixed-size chunk transfer: uses fixed-size chunks for delta negotiation.
    DeltaFixed,
    /// No transfer required: source and destination are already identical.
    Skip,
}

impl std::fmt::Display for TransferMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::DirectStream => write!(f, "direct"),
            Self::DeltaCDC => write!(f, "deltacdc"),
            Self::DeltaFixed => write!(f, "deltafixed"),
            Self::Skip => write!(f, "skip"),
        }
    }
}

impl std::str::FromStr for TransferMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "direct" | "full" | "stream" => Ok(Self::DirectStream),
            "deltacdc" | "cdc" | "fastcdc" => Ok(Self::DeltaCDC),
            "deltafixed" | "delta" => Ok(Self::DeltaFixed),
            "skip" => Ok(Self::Skip),
            _ => Err(format!(
                "unknown transfer mode '{}': expected auto, direct, deltacdc, deltafixed, skip",
                s
            )),
        }
    }
}

/// Network latency, bandwidth, and loss characterization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkProfile {
    /// Estimated available bandwidth in bytes per second (e.g. 125_000_000 for 1 Gbps).
    pub bandwidth_bytes_per_sec: u64,
    /// Round-trip latency.
    pub rtt: Duration,
    /// Estimated packet loss rate (0.0 to 1.0).
    pub packet_loss_rate: f64,
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self::wan_fast()
    }
}

impl NetworkProfile {
    /// Local Area Network preset: 10 Gbps, 0.5 ms RTT, 0.0% loss.
    pub fn lan() -> Self {
        Self {
            bandwidth_bytes_per_sec: 1_250_000_000, // 10 Gbps (1.25 GB/s)
            rtt: Duration::from_micros(500),
            packet_loss_rate: 0.0,
        }
    }

    /// Fast WAN preset: 100 Mbps, 30 ms RTT, 0.1% loss.
    pub fn wan_fast() -> Self {
        Self {
            bandwidth_bytes_per_sec: 12_500_000, // 100 Mbps (12.5 MB/s)
            rtt: Duration::from_millis(30),
            packet_loss_rate: 0.001,
        }
    }

    /// High-latency / Satellite WAN preset: 15 Mbps, 250 ms RTT, 2.0% loss.
    pub fn wan_satellite() -> Self {
        Self {
            bandwidth_bytes_per_sec: 1_875_000, // 15 Mbps (1.875 MB/s)
            rtt: Duration::from_millis(250),
            packet_loss_rate: 0.02,
        }
    }

    /// Construct a network profile dynamically from live QUIC transport stats.
    pub fn from_transport_stats(stats: &TransportStats, fallback_bw: u64) -> Self {
        let rtt = stats.rtt.unwrap_or_else(|| Duration::from_millis(25));
        let rtt_secs = rtt.as_secs_f64().max(0.0001);

        // Derive estimated bandwidth from Congestion Window (BDP = cwnd = bw * rtt)
        let bandwidth_bytes_per_sec = if stats.cwnd > 0 && rtt_secs > 0.0 {
            let derived_bw = (stats.cwnd as f64 / rtt_secs) as u64;
            // Floor at 64 KB/s, cap at 100 GB/s to avoid overflow or div-by-zero
            derived_bw.clamp(64 * 1024, 12_500_000_000)
        } else {
            fallback_bw.max(64 * 1024)
        };

        let packet_loss_rate = if stats.loss_events > 0 {
            let total_events = stats.loss_events + stats.retransmits.max(100);
            (stats.loss_events as f64 / total_events as f64).clamp(0.0, 0.5)
        } else {
            0.0
        };

        Self {
            bandwidth_bytes_per_sec,
            rtt,
            packet_loss_rate,
        }
    }
}

/// Device storage I/O and cryptographic hashing performance profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// Sequential disk read throughput in bytes per second.
    pub disk_read_bps: u64,
    /// Sequential disk write throughput in bytes per second.
    pub disk_write_bps: u64,
    /// BLAKE3 hashing throughput in bytes per second.
    pub hash_bps: u64,
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self::nvme()
    }
}

impl DeviceProfile {
    /// Modern PCIe NVMe SSD preset: 3.0 GB/s read, 2.5 GB/s write, 2.5 GB/s hash.
    pub fn nvme() -> Self {
        Self {
            disk_read_bps: 3_000_000_000,
            disk_write_bps: 2_500_000_000,
            hash_bps: 2_500_000_000,
        }
    }

    /// SATA SSD preset: 550 MB/s read, 500 MB/s write, 1.5 GB/s hash.
    pub fn ssd() -> Self {
        Self {
            disk_read_bps: 550_000_000,
            disk_write_bps: 500_000_000,
            hash_bps: 1_500_000_000,
        }
    }

    /// Spinning HDD preset: 150 MB/s read, 120 MB/s write, 1.0 GB/s hash.
    pub fn hdd() -> Self {
        Self {
            disk_read_bps: 150_000_000,
            disk_write_bps: 120_000_000,
            hash_bps: 1_000_000_000,
        }
    }
}

/// Granular breakdown of estimated transfer durations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostBreakdown {
    /// Duration to send full payload across the wire (seconds).
    pub full_wire_secs: f64,
    /// Duration to write full payload to destination disk (seconds).
    pub full_disk_write_secs: f64,
    /// Network latency overhead for full stream initiation (seconds).
    pub full_rtt_overhead_secs: f64,
    /// Total estimated duration for full direct stream (seconds).
    pub full_total_secs: f64,

    /// Duration to scan and hash local file chunks (seconds).
    pub delta_scan_and_hash_secs: f64,
    /// Round-trip negotiation overhead (InventoryHint + ChunkQuery + ChunkResponse) (seconds).
    pub delta_negotiation_rtt_secs: f64,
    /// Duration to transmit changed delta bytes across the wire (seconds).
    pub delta_wire_secs: f64,
    /// Duration to read reused chunks and write reconstructed staging file (seconds).
    pub delta_reconstruct_secs: f64,
    /// Total estimated duration for delta synchronization (seconds).
    pub delta_total_secs: f64,

    /// Reusable byte volume estimated from similarity.
    pub estimated_reused_bytes: u64,
    /// Estimated data similarity ratio (0.0 = no reuse, 1.0 = identical).
    pub estimated_reuse_ratio: f64,
    /// Estimated time difference: (full_total_secs - delta_total_secs). Positive means delta is faster.
    pub time_savings_secs: f64,
}

/// Decision output produced by the adaptive cost estimator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostDecision {
    /// Selected transfer mode.
    pub recommended_mode: TransferMode,
    /// Whether delta synchronization provides a net benefit over direct streaming.
    pub is_delta_worthwhile: bool,
    /// Estimated time to complete transfer under recommended mode (seconds).
    pub estimated_duration_secs: f64,
    /// Detailed cost model breakdown.
    pub breakdown: CostBreakdown,
    /// Human-readable explanation of why this mode was chosen.
    pub reason: String,
}

/// Empirical cost estimator comparing Direct Transfer vs Delta Synchronization (`REQUIREMENTS.md` §55, §88).
#[derive(Debug, Clone)]
pub struct AdaptiveCostEstimator {
    /// Minimum file size in bytes to even consider delta synchronization.
    /// Transfers smaller than this always default to DirectStream.
    pub min_delta_file_size: u64,
    /// Minimum similarity/reuse ratio (0.0 to 1.0) required to justify delta overhead (default: 0.10 = 10%).
    pub min_savings_ratio: f64,
    /// Number of round-trip times required for delta chunk negotiation (typically 2.0: hint + query/resp).
    pub delta_negotiation_rtts: f64,
    /// Number of round-trip times for direct stream initialization (typically 0.5 to 1.0).
    pub full_stream_rtts: f64,
}

impl Default for AdaptiveCostEstimator {
    fn default() -> Self {
        Self {
            min_delta_file_size: 64 * 1024, // 64 KiB
            min_savings_ratio: 0.08,        // 8% minimum reuse
            delta_negotiation_rtts: 2.0,    // InventoryHint + ChunkQuery/Response
            full_stream_rtts: 0.5,
        }
    }
}

impl AdaptiveCostEstimator {
    /// Create a new adaptive cost estimator with custom thresholds.
    pub fn new(min_delta_file_size: u64, min_savings_ratio: f64) -> Self {
        Self {
            min_delta_file_size,
            min_savings_ratio: min_savings_ratio.clamp(0.0, 1.0),
            ..Self::default()
        }
    }

    /// Evaluate optimal transfer mode given file size, estimated reuse ratio, network and device profiles.
    pub fn evaluate(
        &self,
        file_size: u64,
        estimated_reuse_ratio: f64,
        target_matches: bool,
        net: &NetworkProfile,
        dev: &DeviceProfile,
    ) -> CostDecision {
        let reuse_ratio = estimated_reuse_ratio.clamp(0.0, 1.0);

        // 1. If target matches 100%, skip transfer entirely
        if target_matches || (file_size > 0 && reuse_ratio >= 0.99999) {
            let breakdown = CostBreakdown {
                full_wire_secs: 0.0,
                full_disk_write_secs: 0.0,
                full_rtt_overhead_secs: 0.0,
                full_total_secs: 0.0,
                delta_scan_and_hash_secs: 0.0,
                delta_negotiation_rtt_secs: 0.0,
                delta_wire_secs: 0.0,
                delta_reconstruct_secs: 0.0,
                delta_total_secs: 0.0,
                estimated_reused_bytes: file_size,
                estimated_reuse_ratio: 1.0,
                time_savings_secs: 0.0,
            };
            return CostDecision {
                recommended_mode: TransferMode::Skip,
                is_delta_worthwhile: false,
                estimated_duration_secs: 0.0,
                breakdown,
                reason: "Destination content is already identical (100% match); transfer skipped."
                    .to_string(),
            };
        }

        let net_bw = (net.bandwidth_bytes_per_sec as f64).max(1024.0);
        let rtt_secs = net.rtt.as_secs_f64();
        let disk_read = (dev.disk_read_bps as f64).max(1_000_000.0);
        let disk_write = (dev.disk_write_bps as f64).max(1_000_000.0);
        let hash_speed = (dev.hash_bps as f64).max(1_000_000.0);

        let size_f = file_size as f64;

        // Model: Full Direct Stream
        let full_wire_secs = size_f / net_bw;
        let full_disk_write_secs = size_f / disk_write;
        let full_rtt_overhead_secs = self.full_stream_rtts * rtt_secs;
        let full_total_secs = full_wire_secs + full_disk_write_secs + full_rtt_overhead_secs;

        // Model: Delta CDC Synchronization
        // Cost 1: Reading and hashing file locally
        let scan_bottleneck = disk_read.min(hash_speed);
        let delta_scan_and_hash_secs = size_f / scan_bottleneck;

        // Cost 2: Network RTT rounds for hint, query, response
        let delta_negotiation_rtt_secs = self.delta_negotiation_rtts * rtt_secs;

        // Cost 3: Transmitting changed wire bytes
        let changed_ratio = 1.0 - reuse_ratio;
        let changed_bytes = (size_f * changed_ratio).round() as u64;
        let reused_bytes = file_size.saturating_sub(changed_bytes);
        let delta_wire_secs = (changed_bytes as f64) / net_bw;

        // Cost 4: Destination reconstruction (reading local matches + writing destination staging)
        let delta_reconstruct_read_secs = (reused_bytes as f64) / disk_read;
        let delta_reconstruct_write_secs = size_f / disk_write;
        let delta_reconstruct_secs = delta_reconstruct_read_secs + delta_reconstruct_write_secs;

        let delta_total_secs = delta_scan_and_hash_secs
            + delta_negotiation_rtt_secs
            + delta_wire_secs
            + delta_reconstruct_secs;

        let time_savings_secs = full_total_secs - delta_total_secs;

        let breakdown = CostBreakdown {
            full_wire_secs,
            full_disk_write_secs,
            full_rtt_overhead_secs,
            full_total_secs,
            delta_scan_and_hash_secs,
            delta_negotiation_rtt_secs,
            delta_wire_secs,
            delta_reconstruct_secs,
            delta_total_secs,
            estimated_reused_bytes: reused_bytes,
            estimated_reuse_ratio: reuse_ratio,
            time_savings_secs,
        };

        // Decision logic
        if file_size < self.min_delta_file_size {
            return CostDecision {
                recommended_mode: TransferMode::DirectStream,
                is_delta_worthwhile: false,
                estimated_duration_secs: full_total_secs,
                breakdown,
                reason: format!(
                    "File size ({} B) is below delta threshold ({} B); direct stream is faster.",
                    file_size, self.min_delta_file_size
                ),
            };
        }

        if reuse_ratio < self.min_savings_ratio {
            return CostDecision {
                recommended_mode: TransferMode::DirectStream,
                is_delta_worthwhile: false,
                estimated_duration_secs: full_total_secs,
                breakdown,
                reason: format!(
                    "Estimated reuse ({:.1}%) is below minimum savings threshold ({:.1}%); direct stream avoids wasted scan overhead.",
                    reuse_ratio * 100.0,
                    self.min_savings_ratio * 100.0
                ),
            };
        }

        // Check if delta calculation and negotiation is empirically faster than full stream
        if time_savings_secs > 0.005 {
            // Delta is noticeably faster
            CostDecision {
                recommended_mode: TransferMode::DeltaCDC,
                is_delta_worthwhile: true,
                estimated_duration_secs: delta_total_secs,
                breakdown,
                reason: format!(
                    "Delta sync saves {:.2}s ({:.2}s vs {:.2}s) with {:.1}% data reuse on {} link.",
                    time_savings_secs,
                    delta_total_secs,
                    full_total_secs,
                    reuse_ratio * 100.0,
                    if rtt_secs > 0.05 { "WAN" } else { "LAN" }
                ),
            }
        } else {
            // Full direct stream is faster (e.g. high bandwidth LAN where disk scan bottleneck > wire transfer)
            CostDecision {
                recommended_mode: TransferMode::DirectStream,
                is_delta_worthwhile: false,
                estimated_duration_secs: full_total_secs,
                breakdown,
                reason: format!(
                    "Direct stream is faster ({:.2}s vs {:.2}s); high link bandwidth ({} B/s) outperforms disk scan + negotiation overhead.",
                    full_total_secs, delta_total_secs, net.bandwidth_bytes_per_sec
                ),
            }
        }
    }

    /// Fast preliminary decision from a received Bloom filter similarity estimate.
    pub fn evaluate_from_bloom_match(
        &self,
        file_size: u64,
        matching_chunks: usize,
        total_chunks: usize,
        net: &NetworkProfile,
        dev: &DeviceProfile,
    ) -> CostDecision {
        let reuse_ratio = if total_chunks > 0 {
            matching_chunks as f64 / total_chunks as f64
        } else {
            0.0
        };
        self.evaluate(file_size, reuse_ratio, false, net, dev)
    }
}
