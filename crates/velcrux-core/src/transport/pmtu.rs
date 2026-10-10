//! Network Path MTU Discovery (PMTU / DPLPMTUD RFC 8899), Blackhole Detection,
//! and NAT Firewall Traversal Coordinator (Option AT).
//!
//! (`REQUIREMENTS.md` §75; RFC 8899; RFC 9000; `OPERATIONS.md` §28).
//!
//! Features:
//! 1. Datagram Packetization Layer PMTU Discovery (DPLPMTUD) searching candidate
//!    packet sizes: [1200, 1280, 1420, 1500, 2048, 4096, 9000].
//! 2. Path MTU Blackhole Detection: dynamically catches upstream PMTU drops
//!    and downshifts to base safe MTU (1200 bytes) without connection tears.
//! 3. Stateful NAT / Firewall Keepalive Coordinator: adapts UDP keepalive intervals
//!    (5s..30s) to keep translation tables active and prevent silent connection drops.
//! 4. Comprehensive NAT Diagnostics Reporting for firewall operators.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// RFC 9000 minimum QUIC datagram size (IPv4/IPv6 guaranteed base).
pub const BASE_PLPMTU: u16 = 1200;

/// IPv6 minimum path MTU.
pub const IPV6_MIN_MTU: u16 = 1280;

/// Standard Ethernet MTU.
pub const STANDARD_ETHERNET_MTU: u16 = 1500;

/// Jumbo frame MTU for high-speed data center WANs.
pub const JUMBO_FRAME_MTU: u16 = 9000;

/// Default candidate probe sizes in ascending order.
pub const DEFAULT_PMTU_CANDIDATES: &[u16] = &[1200, 1280, 1420, 1500, 2048, 4096, 9000];

/// State of the DPLPMTUD state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PmtuState {
    /// Safe minimum baseline (1200 bytes).
    Base,
    /// Actively probing candidate packet sizes.
    Searching,
    /// Optimal path MTU confirmed.
    SearchComplete,
    /// Blackhole detected; safe fallback active.
    BlackholeRecovery,
}

impl PmtuState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Searching => "searching",
            Self::SearchComplete => "search_complete",
            Self::BlackholeRecovery => "blackhole_recovery",
        }
    }
}

/// Configuration tunables for PMTU discovery.
#[derive(Debug, Clone)]
pub struct PmtuConfig {
    pub base_mtu: u16,
    pub max_mtu: u16,
    pub max_probe_attempts: u32,
    pub blackhole_loss_threshold: u32,
    pub candidates: Vec<u16>,
}

impl Default for PmtuConfig {
    fn default() -> Self {
        Self {
            base_mtu: BASE_PLPMTU,
            max_mtu: JUMBO_FRAME_MTU,
            max_probe_attempts: 3,
            blackhole_loss_threshold: 4,
            candidates: DEFAULT_PMTU_CANDIDATES.to_vec(),
        }
    }
}

/// Statistics collected by the PMTU discovery engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PmtuStats {
    pub current_mtu: u16,
    pub state: PmtuState,
    pub probes_sent: u64,
    pub probes_acked: u64,
    pub probes_lost: u64,
    pub blackhole_events: u64,
}

/// Datagram Packetization Layer Path MTU Discovery coordinator.
#[derive(Debug)]
pub struct PmtuCoordinator {
    config: PmtuConfig,
    state: PmtuState,
    current_mtu: u16,
    candidate_idx: usize,
    current_probe_attempts: u32,
    consecutive_data_losses: u32,
    probes_sent: u64,
    probes_acked: u64,
    probes_lost: u64,
    blackhole_events: u64,
}

impl PmtuCoordinator {
    /// Create new coordinator using provided configuration.
    pub fn new(config: PmtuConfig) -> Self {
        let base = config.base_mtu;
        Self {
            config,
            state: PmtuState::Base,
            current_mtu: base,
            candidate_idx: 1, // Start probing candidate > base
            current_probe_attempts: 0,
            consecutive_data_losses: 0,
            probes_sent: 0,
            probes_acked: 0,
            probes_lost: 0,
            blackhole_events: 0,
        }
    }

    /// Current validated Path MTU in bytes.
    pub fn current_mtu(&self) -> u16 {
        self.current_mtu
    }

    /// Current PMTU state machine state.
    pub fn state(&self) -> PmtuState {
        self.state
    }

    /// Start or advance PMTU probing. Returns next candidate probe size if probing is active.
    pub fn next_probe_size(&mut self) -> Option<u16> {
        if self.state == PmtuState::SearchComplete {
            return None;
        }

        if self.candidate_idx >= self.config.candidates.len() {
            self.state = PmtuState::SearchComplete;
            return None;
        }

        let target = self.config.candidates[self.candidate_idx];
        if target > self.config.max_mtu {
            self.state = PmtuState::SearchComplete;
            return None;
        }

        self.state = PmtuState::Searching;
        self.probes_sent += 1;
        self.current_probe_attempts += 1;
        Some(target)
    }

    /// Process acknowledgement of a probe packet.
    pub fn on_probe_ack(&mut self, probed_size: u16) {
        if probed_size > self.current_mtu {
            self.current_mtu = probed_size;
            self.probes_acked += 1;
            self.current_probe_attempts = 0;
            self.consecutive_data_losses = 0;

            // Move to next candidate
            self.candidate_idx += 1;
            if self.candidate_idx >= self.config.candidates.len()
                || self.config.candidates[self.candidate_idx] > self.config.max_mtu
            {
                self.state = PmtuState::SearchComplete;
            } else {
                self.state = PmtuState::Searching;
            }
        }
    }

    /// Process loss/timeout of a probe packet.
    pub fn on_probe_loss(&mut self, probed_size: u16) {
        self.probes_lost += 1;
        if self.current_probe_attempts >= self.config.max_probe_attempts {
            // Reached maximum attempts for this size: search terminates at last validated MTU
            self.state = PmtuState::SearchComplete;
            self.current_probe_attempts = 0;
        } else {
            // Keep searching same candidate
            self.state = PmtuState::Searching;
        }
        let _ = probed_size;
    }

    /// Normal data packet acknowledged: clears consecutive data loss counters.
    pub fn on_data_ack(&mut self) {
        self.consecutive_data_losses = 0;
        if self.state == PmtuState::BlackholeRecovery {
            // Resume searching after recovery
            self.state = PmtuState::Searching;
        }
    }

    /// Normal data packet lost: triggers blackhole detection if threshold exceeded.
    /// Returns true if a blackhole event was detected and handled.
    pub fn on_data_loss(&mut self) -> bool {
        self.consecutive_data_losses += 1;
        if self.current_mtu > self.config.base_mtu
            && self.consecutive_data_losses >= self.config.blackhole_loss_threshold
        {
            // Path MTU Blackhole detected! Downshift immediately to safe base MTU
            self.current_mtu = self.config.base_mtu;
            self.state = PmtuState::BlackholeRecovery;
            self.blackhole_events += 1;
            self.candidate_idx = 1;
            self.current_probe_attempts = 0;
            self.consecutive_data_losses = 0;
            true
        } else {
            false
        }
    }

    /// Snapshot current PMTU statistics.
    pub fn stats(&self) -> PmtuStats {
        PmtuStats {
            current_mtu: self.current_mtu,
            state: self.state,
            probes_sent: self.probes_sent,
            probes_acked: self.probes_acked,
            probes_lost: self.probes_lost,
            blackhole_events: self.blackhole_events,
        }
    }
}

/// NAT binding status observed on the transport path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatBindingStatus {
    /// Direct connectivity / public routable IP.
    Direct,
    /// Stateful NAT detected with active pinhole.
    Natted,
    /// IP/port re-binding detected across connection migration.
    RebindingDetected,
}

/// Comprehensive diagnostics report for firewall & NAT operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatDiagnosticsReport {
    pub local_bind_addr: String,
    pub binding_status: NatBindingStatus,
    pub active_keepalive_secs: u64,
    pub current_path_mtu: u16,
    pub pmtu_state: PmtuState,
    pub rebinding_events: u64,
    pub recommendations: Vec<String>,
}

/// Stateful NAT & Firewall Traversal Coordinator.
#[derive(Debug)]
pub struct NatTraversalCoordinator {
    base_keepalive: Duration,
    min_keepalive: Duration,
    max_keepalive: Duration,
    current_keepalive: Duration,
    last_activity: Instant,
    binding_status: NatBindingStatus,
    rebinding_events: u64,
}

impl Default for NatTraversalCoordinator {
    fn default() -> Self {
        Self::new(Duration::from_secs(15))
    }
}

impl NatTraversalCoordinator {
    /// Create new coordinator with standard baseline keepalive (default 15s).
    pub fn new(base_keepalive: Duration) -> Self {
        Self {
            base_keepalive,
            min_keepalive: Duration::from_secs(5),
            max_keepalive: Duration::from_secs(30),
            current_keepalive: base_keepalive,
            last_activity: Instant::now(),
            binding_status: NatBindingStatus::Direct,
            rebinding_events: 0,
        }
    }

    /// Baseline configured keepalive interval.
    pub fn base_keepalive(&self) -> Duration {
        self.base_keepalive
    }

    /// Maximum keepalive interval ceiling.
    pub fn max_keepalive(&self) -> Duration {
        self.max_keepalive
    }

    /// Record outbound or inbound packet activity to reset idle timer.
    pub fn on_packet_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Record observed NAT rebinding event (e.g. source port shift or path migration).
    pub fn on_rebind_detected(&mut self) {
        self.rebinding_events += 1;
        self.binding_status = NatBindingStatus::RebindingDetected;
        // Aggressively tighten keepalive to prevent premature NAT table expiration
        self.current_keepalive = self
            .current_keepalive
            .saturating_sub(Duration::from_secs(5))
            .max(self.min_keepalive);
    }

    /// Mark endpoint as operating behind stateful NAT.
    pub fn mark_natted(&mut self) {
        if self.binding_status != NatBindingStatus::RebindingDetected {
            self.binding_status = NatBindingStatus::Natted;
        }
    }

    /// Whether an idle keepalive ping must be transmitted to refresh the NAT pinhole.
    pub fn should_send_keepalive(&self) -> bool {
        self.last_activity.elapsed() >= self.current_keepalive
    }

    /// Currently active keepalive interval.
    pub fn active_keepalive(&self) -> Duration {
        self.current_keepalive
    }

    /// Generate human-readable diagnostics and operational firewall guidance.
    pub fn diagnostics_report(
        &self,
        local_bind_addr: SocketAddr,
        pmtu: &PmtuCoordinator,
    ) -> NatDiagnosticsReport {
        let mut recs = Vec::new();
        recs.push(format!(
            "Allow UDP traffic inbound/outbound on port {}",
            local_bind_addr.port()
        ));
        recs.push("Configure stateful UDP firewall timeout >= 60s for high throughput".to_string());
        if pmtu.current_mtu() < STANDARD_ETHERNET_MTU {
            recs.push(
                "Verify ICMP Type 3 Code 4 (Fragmentation Needed) is not blocked upstream"
                    .to_string(),
            );
        }
        if self.rebinding_events > 0 {
            recs.push(
                "Symmetric NAT detected: connection migration will dynamically re-bind".to_string(),
            );
        }

        NatDiagnosticsReport {
            local_bind_addr: local_bind_addr.to_string(),
            binding_status: self.binding_status,
            active_keepalive_secs: self.current_keepalive.as_secs(),
            current_path_mtu: pmtu.current_mtu(),
            pmtu_state: pmtu.state(),
            rebinding_events: self.rebinding_events,
            recommendations: recs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmtu_step_search_success() {
        let config = PmtuConfig::default();
        let mut coord = PmtuCoordinator::new(config);

        assert_eq!(coord.current_mtu(), BASE_PLPMTU);
        assert_eq!(coord.state(), PmtuState::Base);

        // Probe 1280
        let p1 = coord.next_probe_size().unwrap();
        assert_eq!(p1, 1280);
        assert_eq!(coord.state(), PmtuState::Searching);
        coord.on_probe_ack(1280);
        assert_eq!(coord.current_mtu(), 1280);

        // Probe 1420
        let p2 = coord.next_probe_size().unwrap();
        assert_eq!(p2, 1420);
        coord.on_probe_ack(1420);
        assert_eq!(coord.current_mtu(), 1420);

        // Probe 1500
        let p3 = coord.next_probe_size().unwrap();
        assert_eq!(p3, 1500);
        coord.on_probe_ack(1500);
        assert_eq!(coord.current_mtu(), 1500);

        // Probe 2048: simulate probe loss up to max attempts (3 probes)
        let p4 = coord.next_probe_size().unwrap();
        assert_eq!(p4, 2048);
        coord.on_probe_loss(2048);

        let p4_retry1 = coord.next_probe_size().unwrap();
        assert_eq!(p4_retry1, 2048);
        coord.on_probe_loss(2048);

        let p4_retry2 = coord.next_probe_size().unwrap();
        assert_eq!(p4_retry2, 2048);
        coord.on_probe_loss(2048); // 3rd failure

        // Search completes, current MTU remains 1500
        assert_eq!(coord.state(), PmtuState::SearchComplete);
        assert_eq!(coord.current_mtu(), 1500);
        assert_eq!(coord.next_probe_size(), None);
    }

    #[test]
    fn test_pmtu_blackhole_detection_and_fallback() {
        let config = PmtuConfig::default();
        let mut coord = PmtuCoordinator::new(config);

        // Advance to 1500 MTU
        coord.next_probe_size();
        coord.on_probe_ack(1280);
        coord.next_probe_size();
        coord.on_probe_ack(1420);
        coord.next_probe_size();
        coord.on_probe_ack(1500);
        assert_eq!(coord.current_mtu(), 1500);

        // Standard traffic experiences consecutive losses
        assert!(!coord.on_data_loss());
        assert!(!coord.on_data_loss());
        assert!(!coord.on_data_loss());
        // 4th loss triggers blackhole recovery
        assert!(coord.on_data_loss());

        // Assert emergency downshift to 1200 safe base
        assert_eq!(coord.current_mtu(), BASE_PLPMTU);
        assert_eq!(coord.state(), PmtuState::BlackholeRecovery);

        let stats = coord.stats();
        assert_eq!(stats.blackhole_events, 1);
        assert_eq!(stats.current_mtu, 1200);

        // Normal data ack restores searching capability
        coord.on_data_ack();
        assert_eq!(coord.state(), PmtuState::Searching);
    }

    #[test]
    fn test_nat_traversal_keepalive_adaptation() {
        let mut nat = NatTraversalCoordinator::new(Duration::from_secs(15));
        assert_eq!(nat.active_keepalive(), Duration::from_secs(15));

        // Detect rebinding -> tighter keepalive
        nat.on_rebind_detected();
        assert_eq!(nat.active_keepalive(), Duration::from_secs(10));

        nat.on_rebind_detected();
        assert_eq!(nat.active_keepalive(), Duration::from_secs(5));

        // Does not shrink below min_keepalive (5s)
        nat.on_rebind_detected();
        assert_eq!(nat.active_keepalive(), Duration::from_secs(5));
    }

    #[test]
    fn test_nat_diagnostics_report() {
        let pmtu = PmtuCoordinator::new(PmtuConfig::default());
        let mut nat = NatTraversalCoordinator::default();
        nat.mark_natted();

        let bind_addr: SocketAddr = "0.0.0.0:7443".parse().unwrap();
        let report = nat.diagnostics_report(bind_addr, &pmtu);

        assert_eq!(report.local_bind_addr, "0.0.0.0:7443");
        assert_eq!(report.binding_status, NatBindingStatus::Natted);
        assert_eq!(report.current_path_mtu, 1200);
        assert!(report.recommendations.len() >= 2);
    }
}
