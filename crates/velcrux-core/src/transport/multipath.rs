//! Multi-Interface Bonding & Multi-Path QUIC Transport Aggregation (Option AX).
//!
//! Conforms to `REQUIREMENTS.md` §74 ("Multi-Path Future"), §75 ("NAT and Firewall Considerations"),
//! RFC 9000, and RFC 9369 (Multipath QUIC).
//!
//! Provides simultaneous aggregation across multiple physical/virtual interfaces (Wi-Fi,
//! 10GbE, 5G/cellular), dynamic subflow path quality scoring, multi-path chunk scheduling,
//! path degradation gating, and zero-downtime hot failover.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::error::VelcruxError;
use crate::transport::interface::list_interfaces;

/// Operational health state of a subflow path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathState {
    /// Path is healthy, responsive, and actively handling traffic.
    Active,
    /// Path experiencing elevated latency or transient packet loss; throttled.
    Degraded,
    /// Path is under active probing / RTT measurement before being re-admitted.
    Probing,
    /// Path is unresponsive, timed out, or interface link is administratively down.
    Dead,
}

impl PathState {
    /// True if the path can accept outgoing payload traffic.
    pub fn is_routable(&self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

/// Scheduling strategy for distributing data chunks across bonded subflow paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultipathSchedulerPolicy {
    /// Round-robin chunk distribution across all active paths.
    RoundRobin,
    /// Bandwidth-proportional distribution: traffic split proportionally to measured BDP / throughput.
    WeightedBandwidth,
    /// Lowest-latency-first: route traffic to the lowest RTT path, spilling over when cwnd is full.
    LowestLatencyFirst,
    /// Redundant: duplicate chunks across multiple active paths for lossy/critical WAN links.
    Redundant,
    /// Primary-backup: route 100% of traffic to primary path; hot-failover to backup if degraded/dead.
    PrimaryBackup,
}

impl MultipathSchedulerPolicy {
    /// Parse strategy from string CLI / config token.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "round_robin" | "rr" => Some(Self::RoundRobin),
            "weighted" | "weighted_bandwidth" | "bw" => Some(Self::WeightedBandwidth),
            "min_rtt" | "lowest_latency" | "latency" => Some(Self::LowestLatencyFirst),
            "redundant" | "dup" | "duplication" => Some(Self::Redundant),
            "failover" | "primary_backup" | "backup" => Some(Self::PrimaryBackup),
            _ => None,
        }
    }

    /// Canonical machine name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::WeightedBandwidth => "weighted_bandwidth",
            Self::LowestLatencyFirst => "lowest_latency_first",
            Self::Redundant => "redundant",
            Self::PrimaryBackup => "primary_backup",
        }
    }
}

/// Dynamic path quality metrics for a bonded subflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubflowQualityMetrics {
    /// Current measured Round-Trip Time.
    pub rtt_ms: f64,
    /// Smoothed RTT (exponential moving average).
    pub smoothed_rtt_ms: f64,
    /// Estimated packet / chunk loss rate (0.0 to 1.0).
    pub loss_rate: f64,
    /// Congestion window in bytes.
    pub cwnd_bytes: u64,
    /// Bytes in flight on this path.
    pub bytes_in_flight: u64,
    /// Estimated throughput capacity in bits per second.
    pub estimated_bw_bps: u64,
}

impl Default for SubflowQualityMetrics {
    fn default() -> Self {
        Self {
            rtt_ms: 20.0,
            smoothed_rtt_ms: 20.0,
            loss_rate: 0.0,
            cwnd_bytes: 1024 * 1024,
            bytes_in_flight: 0,
            estimated_bw_bps: 100_000_000, // 100 Mbps default
        }
    }
}

/// Descriptor of an individual bonded subflow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubflowPathDescriptor {
    /// Unique identifier for this subflow within the bonding session.
    pub path_id: usize,
    /// Local network interface name (e.g. "eth0", "wlan0").
    pub interface_name: String,
    /// Bound local IP address.
    pub local_addr: SocketAddr,
    /// Remote destination socket address.
    pub remote_addr: SocketAddr,
    /// Current operational health state.
    pub state: PathState,
    /// Configured weight multiplier (default 1).
    pub configured_weight: u32,
    /// Is this interface designated as the primary link?
    pub is_primary: bool,
    /// Path quality metrics.
    pub metrics: SubflowQualityMetrics,
    /// Total bytes transmitted across this subflow.
    pub total_bytes_sent: u64,
    /// Total bytes acknowledged across this subflow.
    pub total_bytes_acked: u64,
}

/// Internal state tracking for an active subflow path.
#[derive(Debug)]
struct SubflowPath {
    id: usize,
    interface_name: String,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    state: PathState,
    configured_weight: u32,
    is_primary: bool,
    metrics: SubflowQualityMetrics,
    total_bytes_sent: AtomicU64,
    total_bytes_acked: AtomicU64,
    consecutive_failures: usize,
    last_rtt_update: Instant,
}

impl SubflowPath {
    fn new(
        id: usize,
        interface_name: String,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        configured_weight: u32,
        is_primary: bool,
    ) -> Self {
        Self {
            id,
            interface_name,
            local_addr,
            remote_addr,
            state: PathState::Active,
            configured_weight: configured_weight.max(1),
            is_primary,
            metrics: SubflowQualityMetrics::default(),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_acked: AtomicU64::new(0),
            consecutive_failures: 0,
            last_rtt_update: Instant::now(),
        }
    }

    fn to_descriptor(&self) -> SubflowPathDescriptor {
        SubflowPathDescriptor {
            path_id: self.id,
            interface_name: self.interface_name.clone(),
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            state: self.state,
            configured_weight: self.configured_weight,
            is_primary: self.is_primary,
            metrics: self.metrics.clone(),
            total_bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
            total_bytes_acked: self.total_bytes_acked.load(Ordering::Relaxed),
        }
    }
}

/// Configuration options for the Multi-Path Bonding Manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipathConfig {
    /// Enable multi-path transport bonding.
    pub enabled: bool,
    /// Scheduling policy.
    pub policy: MultipathSchedulerPolicy,
    /// Specific interface names to bind (empty = auto-discover all non-loopback UP interfaces).
    pub interface_whitelist: Vec<String>,
    /// Primary interface name (for PrimaryBackup policy).
    pub primary_interface: Option<String>,
    /// RTT threshold in milliseconds above which a path transitions to Degraded (default: 150.0).
    pub rtt_degraded_threshold_ms: f64,
    /// Packet loss rate threshold above which a path transitions to Degraded (default: 0.15 = 15%).
    pub loss_degraded_threshold: f64,
    /// Consecutive timeouts/failures before marking a path Dead (default: 3).
    pub max_consecutive_failures: usize,
    /// Probing interval for dead/degraded paths in milliseconds (default: 1000).
    pub probe_interval_ms: u64,
    /// Duplicate critical control & metadata frames across all active paths.
    pub duplicate_metadata: bool,
}

impl Default for MultipathConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: MultipathSchedulerPolicy::WeightedBandwidth,
            interface_whitelist: Vec::new(),
            primary_interface: None,
            rtt_degraded_threshold_ms: 150.0,
            loss_degraded_threshold: 0.15,
            max_consecutive_failures: 3,
            probe_interval_ms: 1000,
            duplicate_metadata: true,
        }
    }
}

/// Summary report of aggregated multipath transport performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipathSessionReport {
    /// Active scheduler policy.
    pub policy: String,
    /// Number of bonded subflow paths configured.
    pub total_paths: usize,
    /// Number of paths currently Active.
    pub active_paths: usize,
    /// Number of paths currently Degraded.
    pub degraded_paths: usize,
    /// Number of paths currently Dead.
    pub dead_paths: usize,
    /// Aggregate bandwidth capacity in Mbps.
    pub aggregate_bandwidth_mbps: f64,
    /// Total bytes dispatched across all paths.
    pub total_bytes_sent: u64,
    /// Total bytes acknowledged across all paths.
    pub total_bytes_acked: u64,
    /// Reordering skew between fastest and slowest subflows (ms).
    pub reordering_skew_ms: f64,
    /// Subflow path descriptors.
    pub paths: Vec<SubflowPathDescriptor>,
}

/// Multi-Interface Bonding & Multi-Path QUIC Transport Coordinator.
#[derive(Debug)]
pub struct MultipathCoordinator {
    config: MultipathConfig,
    paths: RwLock<Vec<SubflowPath>>,
    rr_cursor: AtomicUsize,
    total_scheduled: AtomicU64,
}

impl MultipathCoordinator {
    /// Create a new coordinator with the given configuration.
    pub fn new(config: MultipathConfig) -> Self {
        Self {
            config,
            paths: RwLock::new(Vec::new()),
            rr_cursor: AtomicUsize::new(0),
            total_scheduled: AtomicU64::new(0),
        }
    }

    /// Access the configuration.
    pub fn config(&self) -> &MultipathConfig {
        &self.config
    }

    /// Automatically discover local interfaces and initialize bonded subflow paths.
    pub fn auto_discover_and_bind(&self, remote_target: SocketAddr) -> Result<usize, VelcruxError> {
        let available = list_interfaces();
        let mut added = 0;

        for iface in available {
            if iface.is_loopback || !iface.is_up {
                continue;
            }

            if !self.config.interface_whitelist.is_empty()
                && !self.config.interface_whitelist.contains(&iface.name)
            {
                continue;
            }

            if let Some(bind_ip) = iface.matching_ip_for_target(Some(remote_target)) {
                let local_socket = SocketAddr::new(bind_ip, 0);
                let is_prim = self
                    .config
                    .primary_interface
                    .as_ref()
                    .map(|p| p == &iface.name)
                    .unwrap_or(added == 0);

                self.add_subflow_path(iface.name.clone(), local_socket, remote_target, 1, is_prim);
                added += 1;
            }
        }

        // If no interfaces matched or auto-discovered, bind default wildcards
        if added == 0 {
            let default_ip = if remote_target.is_ipv6() {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            };
            self.add_subflow_path(
                "default".to_string(),
                SocketAddr::new(default_ip, 0),
                remote_target,
                1,
                true,
            );
            added += 1;
        }

        Ok(added)
    }

    /// Manually register a subflow path.
    pub fn add_subflow_path(
        &self,
        interface_name: String,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        weight: u32,
        is_primary: bool,
    ) -> usize {
        let mut paths = self.paths.write().unwrap();
        let path_id = paths.len();
        paths.push(SubflowPath::new(
            path_id,
            interface_name,
            local_addr,
            remote_addr,
            weight,
            is_primary,
        ));
        path_id
    }

    /// Retrieve number of registered paths.
    pub fn path_count(&self) -> usize {
        self.paths.read().unwrap().len()
    }

    /// Retrieve number of currently routable (Active or Degraded) paths.
    pub fn routable_path_count(&self) -> usize {
        self.paths
            .read()
            .unwrap()
            .iter()
            .filter(|p| p.state.is_routable())
            .count()
    }

    /// Record a telemetry RTT and loss sample on a specific subflow path.
    pub fn record_path_sample(
        &self,
        path_id: usize,
        rtt: Duration,
        loss_rate: f64,
        cwnd_bytes: u64,
        in_flight: u64,
    ) {
        let mut paths = self.paths.write().unwrap();
        if let Some(path) = paths.get_mut(path_id) {
            let rtt_ms = rtt.as_secs_f64() * 1000.0;
            path.metrics.rtt_ms = rtt_ms;

            // Exponential Moving Average (alpha = 0.125 per RFC 6298)
            let alpha = 0.125;
            path.metrics.smoothed_rtt_ms =
                (1.0 - alpha) * path.metrics.smoothed_rtt_ms + alpha * rtt_ms;
            path.metrics.loss_rate = loss_rate;
            path.metrics.cwnd_bytes = cwnd_bytes;
            path.metrics.bytes_in_flight = in_flight;

            // Throughput estimate: cwnd / RTT
            let rtt_sec = (rtt_ms / 1000.0).max(0.0001);
            let bw_bps = ((cwnd_bytes as f64 * 8.0) / rtt_sec) as u64;
            path.metrics.estimated_bw_bps = bw_bps;
            path.last_rtt_update = Instant::now();

            // Evaluate state transitions
            if path.metrics.smoothed_rtt_ms > self.config.rtt_degraded_threshold_ms
                || path.metrics.loss_rate > self.config.loss_degraded_threshold
            {
                if path.state == PathState::Active {
                    path.state = PathState::Degraded;
                }
            } else if path.state != PathState::Active {
                path.consecutive_failures = 0;
                path.state = PathState::Active;
            }
        }
    }

    /// Record a timeout or transmission failure on a path.
    pub fn record_path_failure(&self, path_id: usize) {
        let mut paths = self.paths.write().unwrap();
        if let Some(path) = paths.get_mut(path_id) {
            path.consecutive_failures += 1;
            if path.consecutive_failures >= self.config.max_consecutive_failures {
                path.state = PathState::Dead;
            } else {
                path.state = PathState::Degraded;
            }
        }
    }

    /// Record transmitted bytes for a subflow.
    pub fn record_bytes_sent(&self, path_id: usize, bytes: u64) {
        let paths = self.paths.read().unwrap();
        if let Some(path) = paths.get(path_id) {
            path.total_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            self.total_scheduled.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Record acknowledged bytes for a subflow.
    pub fn record_bytes_acked(&self, path_id: usize, bytes: u64) {
        let paths = self.paths.read().unwrap();
        if let Some(path) = paths.get(path_id) {
            path.total_bytes_acked.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Select the next optimal subflow path(s) according to the configured policy.
    ///
    /// For non-redundant modes, returns `vec![path_id]`.
    /// For redundant mode, returns all healthy path IDs for dual/multi transmission.
    pub fn select_path_for_chunk(&self, chunk_size: usize, is_metadata: bool) -> Vec<usize> {
        let paths = self.paths.read().unwrap();
        if paths.is_empty() {
            return Vec::new();
        }

        // If duplicate_metadata is set and this is a metadata frame, dispatch on all active paths
        if is_metadata && self.config.duplicate_metadata {
            let routable: Vec<usize> = paths
                .iter()
                .filter(|p| p.state.is_routable())
                .map(|p| p.id)
                .collect();
            if !routable.is_empty() {
                return routable;
            }
        }

        let routable: Vec<&SubflowPath> = paths.iter().filter(|p| p.state.is_routable()).collect();
        if routable.is_empty() {
            // Emergency fallback: return primary path or first path even if marked degraded/probing
            if let Some(primary) = paths.iter().find(|p| p.is_primary) {
                return vec![primary.id];
            }
            return vec![paths[0].id];
        }

        match self.config.policy {
            MultipathSchedulerPolicy::RoundRobin => {
                let idx = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % routable.len();
                vec![routable[idx].id]
            }

            MultipathSchedulerPolicy::WeightedBandwidth => {
                // Compute total bandwidth-weight sum
                let mut total_weight = 0u64;
                for p in &routable {
                    let weight = (p.configured_weight as u64)
                        * (p.metrics.estimated_bw_bps / 1_000_000).max(1);
                    total_weight += weight;
                }

                if total_weight == 0 {
                    let idx = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % routable.len();
                    return vec![routable[idx].id];
                }

                let cur = self.rr_cursor.fetch_add(1, Ordering::Relaxed) as u64 % total_weight;
                let mut accumulated = 0u64;
                for p in &routable {
                    let weight = (p.configured_weight as u64)
                        * (p.metrics.estimated_bw_bps / 1_000_000).max(1);
                    accumulated += weight;
                    if cur < accumulated {
                        return vec![p.id];
                    }
                }
                vec![routable[0].id]
            }

            MultipathSchedulerPolicy::LowestLatencyFirst => {
                // Find path with lowest smoothed RTT that has available congestion window headroom
                let mut best = routable[0];
                let mut best_rtt = f64::MAX;

                for p in &routable {
                    // Check if window is not choked
                    let headroom = p
                        .metrics
                        .cwnd_bytes
                        .saturating_sub(p.metrics.bytes_in_flight);
                    if headroom >= chunk_size as u64 && p.metrics.smoothed_rtt_ms < best_rtt {
                        best = p;
                        best_rtt = p.metrics.smoothed_rtt_ms;
                    }
                }

                // If all windows are full, fallback to lowest RTT regardless of headroom
                if best_rtt == f64::MAX {
                    for p in &routable {
                        if p.metrics.smoothed_rtt_ms < best_rtt {
                            best = p;
                            best_rtt = p.metrics.smoothed_rtt_ms;
                        }
                    }
                }

                vec![best.id]
            }

            MultipathSchedulerPolicy::Redundant => {
                // Send on all routable paths
                routable.iter().map(|p| p.id).collect()
            }

            MultipathSchedulerPolicy::PrimaryBackup => {
                // Prefer primary if routable and not Dead
                if let Some(prim) = routable
                    .iter()
                    .find(|p| p.is_primary && p.state == PathState::Active)
                {
                    vec![prim.id]
                } else if let Some(prim) = routable.iter().find(|p| p.is_primary) {
                    vec![prim.id]
                } else {
                    // Failover to first available healthy backup
                    vec![routable[0].id]
                }
            }
        }
    }

    /// Generate an aggregate session summary report.
    pub fn generate_report(&self) -> MultipathSessionReport {
        let paths = self.paths.read().unwrap();
        let total_paths = paths.len();
        let mut active_paths = 0;
        let mut degraded_paths = 0;
        let mut dead_paths = 0;
        let mut aggregate_bw_bps = 0u64;
        let mut total_bytes_sent = 0u64;
        let mut total_bytes_acked = 0u64;
        let mut min_rtt = f64::MAX;
        let mut max_rtt = 0.0f64;

        let mut descriptors = Vec::new();
        for p in paths.iter() {
            match p.state {
                PathState::Active => active_paths += 1,
                PathState::Degraded => degraded_paths += 1,
                PathState::Probing | PathState::Dead => dead_paths += 1,
            }

            if p.state.is_routable() {
                aggregate_bw_bps += p.metrics.estimated_bw_bps;
                let rtt = p.metrics.smoothed_rtt_ms;
                if rtt < min_rtt {
                    min_rtt = rtt;
                }
                if rtt > max_rtt {
                    max_rtt = rtt;
                }
            }

            total_bytes_sent += p.total_bytes_sent.load(Ordering::Relaxed);
            total_bytes_acked += p.total_bytes_acked.load(Ordering::Relaxed);
            descriptors.push(p.to_descriptor());
        }

        let reordering_skew_ms = if min_rtt == f64::MAX {
            0.0
        } else {
            (max_rtt - min_rtt).max(0.0)
        };

        MultipathSessionReport {
            policy: self.config.policy.name().to_string(),
            total_paths,
            active_paths,
            degraded_paths,
            dead_paths,
            aggregate_bandwidth_mbps: (aggregate_bw_bps as f64) / 1_000_000.0,
            total_bytes_sent,
            total_bytes_acked,
            reordering_skew_ms,
            paths: descriptors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_socket(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    #[test]
    fn test_multipath_scheduler_round_robin() {
        let mut cfg = MultipathConfig::default();
        cfg.policy = MultipathSchedulerPolicy::RoundRobin;
        let coord = MultipathCoordinator::new(cfg);

        let p1 = coord.add_subflow_path(
            "eth0".into(),
            dummy_socket(1001),
            dummy_socket(7443),
            1,
            true,
        );
        let p2 = coord.add_subflow_path(
            "wlan0".into(),
            dummy_socket(1002),
            dummy_socket(7443),
            1,
            false,
        );

        assert_eq!(coord.path_count(), 2);
        assert_eq!(coord.routable_path_count(), 2);

        let s1 = coord.select_path_for_chunk(1024, false);
        let s2 = coord.select_path_for_chunk(1024, false);
        let s3 = coord.select_path_for_chunk(1024, false);

        assert_eq!(s1, vec![p1]);
        assert_eq!(s2, vec![p2]);
        assert_eq!(s3, vec![p1]);
    }

    #[test]
    fn test_multipath_primary_backup_failover() {
        let mut cfg = MultipathConfig::default();
        cfg.policy = MultipathSchedulerPolicy::PrimaryBackup;
        let coord = MultipathCoordinator::new(cfg);

        let p_prim = coord.add_subflow_path(
            "eth0".into(),
            dummy_socket(1001),
            dummy_socket(7443),
            1,
            true,
        );
        let p_bkup = coord.add_subflow_path(
            "wlan0".into(),
            dummy_socket(1002),
            dummy_socket(7443),
            1,
            false,
        );

        // When primary is Active, select primary
        assert_eq!(coord.select_path_for_chunk(1024, false), vec![p_prim]);

        // Trigger failures on primary until Dead
        coord.record_path_failure(p_prim);
        coord.record_path_failure(p_prim);
        coord.record_path_failure(p_prim);

        // Should automatically failover to backup
        assert_eq!(coord.select_path_for_chunk(1024, false), vec![p_bkup]);

        // If primary recovers, restore to primary
        coord.record_path_sample(p_prim, Duration::from_millis(15), 0.0, 1024 * 1024, 0);
        assert_eq!(coord.select_path_for_chunk(1024, false), vec![p_prim]);
    }

    #[test]
    fn test_multipath_lowest_latency_first() {
        let mut cfg = MultipathConfig::default();
        cfg.policy = MultipathSchedulerPolicy::LowestLatencyFirst;
        let coord = MultipathCoordinator::new(cfg);

        let p_fast = coord.add_subflow_path(
            "eth0".into(),
            dummy_socket(1001),
            dummy_socket(7443),
            1,
            true,
        );
        let p_slow = coord.add_subflow_path(
            "cell0".into(),
            dummy_socket(1002),
            dummy_socket(7443),
            1,
            false,
        );

        // Fast path: 5ms RTT, 1MB cwnd
        coord.record_path_sample(p_fast, Duration::from_millis(5), 0.0, 1_000_000, 0);
        // Slow path: 60ms RTT, 1MB cwnd
        coord.record_path_sample(p_slow, Duration::from_millis(60), 0.0, 1_000_000, 0);

        // Selects lowest RTT
        assert_eq!(coord.select_path_for_chunk(1024, false), vec![p_fast]);

        // When fast path cwnd is choked (bytes_in_flight >= cwnd), spills over to slow path
        coord.record_path_sample(p_fast, Duration::from_millis(5), 0.0, 1_000_000, 1_000_000);
        assert_eq!(coord.select_path_for_chunk(1024, false), vec![p_slow]);
    }

    #[test]
    fn test_multipath_redundant_duplication() {
        let mut cfg = MultipathConfig::default();
        cfg.policy = MultipathSchedulerPolicy::Redundant;
        let coord = MultipathCoordinator::new(cfg);

        let p1 = coord.add_subflow_path(
            "eth0".into(),
            dummy_socket(1001),
            dummy_socket(7443),
            1,
            true,
        );
        let p2 = coord.add_subflow_path(
            "wlan0".into(),
            dummy_socket(1002),
            dummy_socket(7443),
            1,
            false,
        );

        let paths = coord.select_path_for_chunk(1024, false);
        assert_eq!(paths, vec![p1, p2]);
    }

    #[test]
    fn test_multipath_session_reporting() {
        let cfg = MultipathConfig::default();
        let coord = MultipathCoordinator::new(cfg);

        let p1 = coord.add_subflow_path(
            "eth0".into(),
            dummy_socket(1001),
            dummy_socket(7443),
            1,
            true,
        );
        let p2 = coord.add_subflow_path(
            "eth1".into(),
            dummy_socket(1002),
            dummy_socket(7443),
            1,
            false,
        );

        coord.record_bytes_sent(p1, 100_000);
        coord.record_bytes_acked(p1, 95_000);
        coord.record_bytes_sent(p2, 200_000);
        coord.record_bytes_acked(p2, 190_000);

        let report = coord.generate_report();
        assert_eq!(report.total_paths, 2);
        assert_eq!(report.active_paths, 2);
        assert_eq!(report.total_bytes_sent, 300_000);
        assert_eq!(report.total_bytes_acked, 285_000);
    }
}
