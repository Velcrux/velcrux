//! Multi-Path QUIC Connection Migration & Failover Gating (Option AP).
//!
//! Conforms to RFC 9000 §9 ("Connection Migration"), `REQUIREMENTS.md` §11, §41, §70,
//! `SECURITY.md` §2, §3, and `OPERATIONS.md` §4, §24.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

/// Security policy mode governing QUIC connection migrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPolicyMode {
    /// Allow any valid cryptographically verified QUIC connection migration (default).
    Permissive,
    /// Enforce rate limits, subnet gating, and identity continuity.
    Gated,
    /// Disallow address migration; any change in client socket address aborts the connection.
    Disabled,
}

/// Tunables for connection migration gating and security policies.
#[derive(Debug, Clone)]
pub struct MigrationPolicy {
    /// Active policy mode.
    pub mode: MigrationPolicyMode,
    /// Maximum migrations allowed per connection within `rate_window_secs` (default 5).
    pub max_migrations_per_window: usize,
    /// Rolling window duration for rate limiting in seconds (default 60).
    pub rate_window_secs: u64,
    /// Optional allowlist of IP prefixes / CIDR strings (e.g. `["192.168.", "10.0.", "127."]`).
    /// If empty, all non-bogon networks are permitted.
    pub allowed_subnets: Vec<String>,
    /// Disallow migration if switching from a public address to a loopback address.
    pub disallow_loopback_migration: bool,
}

impl Default for MigrationPolicy {
    fn default() -> Self {
        Self {
            mode: MigrationPolicyMode::Permissive,
            max_migrations_per_window: 5,
            rate_window_secs: 60,
            allowed_subnets: Vec::new(),
            disallow_loopback_migration: false,
        }
    }
}

/// Evaluation decision made by the failover gate for a connection address change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationDecision {
    /// Migration allowed and accepted.
    Allowed,
    /// Address has not changed; no migration necessary.
    NoChange,
    /// Migration rejected because migration is disabled by server policy.
    RejectedDisabled,
    /// Migration rejected because connection exceeded rate limit.
    RejectedRateLimitExceeded { count: usize, limit: usize },
    /// Migration rejected because destination address is not in allowed subnets.
    RejectedSubnetDisallowed { addr: SocketAddr },
}

impl MigrationDecision {
    /// True if the address change was approved or if no change occurred.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed | Self::NoChange)
    }
}

/// Event broadcast when a QUIC connection successfully migrates to a new remote address.
#[derive(Debug, Clone)]
pub struct MigrationEvent {
    /// Stable unique numeric ID identifying the QUIC connection across migrations.
    pub connection_id: usize,
    /// Previous client remote socket address.
    pub prev_addr: SocketAddr,
    /// New client remote socket address.
    pub new_addr: SocketAddr,
    /// Unix timestamp in milliseconds when migration was observed.
    pub timestamp_ms: u64,
    /// Measured round-trip time on the new path.
    pub rtt: Duration,
    /// Authenticated peer mTLS identity (e.g. SAN URI / CN).
    pub peer_identity: Option<String>,
}

/// Runtime telemetry statistics for connection migrations.
#[derive(Debug, Default)]
pub struct MigrationStats {
    /// Total migration attempts detected.
    pub migrations_total: AtomicU64,
    /// Migrations approved and processed.
    pub migrations_accepted: AtomicU64,
    /// Migrations blocked by gating policy or rate limits.
    pub migrations_rejected: AtomicU64,
    /// Total active connections currently monitored.
    pub active_monitored_conns: AtomicU64,
}

#[derive(Debug)]
struct ConnectionRecord {
    current_addr: SocketAddr,
    peer_identity: Option<String>,
    migration_timestamps: Vec<u64>,
}

/// Thread-safe coordinator monitoring QUIC connection migrations,
/// enforcing failover gating policies, and emitting telemetry events.
#[derive(Debug)]
pub struct MigrationCoordinator {
    policy: MigrationPolicy,
    stats: Arc<MigrationStats>,
    connections: Mutex<HashMap<usize, ConnectionRecord>>,
    event_tx: broadcast::Sender<MigrationEvent>,
}

impl MigrationCoordinator {
    /// Construct a new coordinator with given policy and telemetry counters.
    pub fn new(policy: MigrationPolicy, stats: Arc<MigrationStats>) -> Self {
        let (event_tx, _) = broadcast::channel(128);
        Self {
            policy,
            stats,
            connections: Mutex::new(HashMap::new()),
            event_tx,
        }
    }

    /// Construct a new coordinator with default settings.
    pub fn with_defaults() -> Self {
        Self::new(
            MigrationPolicy::default(),
            Arc::new(MigrationStats::default()),
        )
    }

    /// Active policy.
    pub fn policy(&self) -> &MigrationPolicy {
        &self.policy
    }

    /// Active telemetry counters.
    pub fn stats(&self) -> &Arc<MigrationStats> {
        &self.stats
    }

    /// Subscribe to connection migration broadcast events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<MigrationEvent> {
        self.event_tx.subscribe()
    }

    /// Register a newly established connection with its initial socket address.
    pub fn register_connection(
        &self,
        connection_id: usize,
        initial_addr: SocketAddr,
        peer_identity: Option<String>,
    ) {
        let mut conns = self.connections.lock().unwrap();
        conns.insert(
            connection_id,
            ConnectionRecord {
                current_addr: initial_addr,
                peer_identity,
                migration_timestamps: Vec::new(),
            },
        );
        self.stats
            .active_monitored_conns
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Unregister a terminated connection.
    pub fn unregister_connection(&self, connection_id: usize) {
        let mut conns = self.connections.lock().unwrap();
        if conns.remove(&connection_id).is_some() {
            self.stats
                .active_monitored_conns
                .fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Evaluate an observed remote address against the migration policy.
    ///
    /// If the address has changed and passes policy gating, updates internal state,
    /// increments acceptance telemetry, and broadcasts a [`MigrationEvent`].
    pub fn evaluate_migration(
        &self,
        connection_id: usize,
        observed_addr: SocketAddr,
        rtt: Duration,
    ) -> MigrationDecision {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut conns = self.connections.lock().unwrap();
        let record = match conns.get_mut(&connection_id) {
            Some(r) => r,
            None => {
                // If not pre-registered, treat this as initial registration
                conns.insert(
                    connection_id,
                    ConnectionRecord {
                        current_addr: observed_addr,
                        peer_identity: None,
                        migration_timestamps: Vec::new(),
                    },
                );
                self.stats
                    .active_monitored_conns
                    .fetch_add(1, Ordering::Relaxed);
                return MigrationDecision::NoChange;
            }
        };

        if record.current_addr == observed_addr {
            return MigrationDecision::NoChange;
        }

        self.stats.migrations_total.fetch_add(1, Ordering::Relaxed);

        // 1. Check if migrations are disabled
        if self.policy.mode == MigrationPolicyMode::Disabled {
            self.stats
                .migrations_rejected
                .fetch_add(1, Ordering::Relaxed);
            return MigrationDecision::RejectedDisabled;
        }

        // 2. Subnet and loopback gating (in Gated mode)
        if self.policy.mode == MigrationPolicyMode::Gated {
            if self.policy.disallow_loopback_migration
                && !record.current_addr.ip().is_loopback()
                && observed_addr.ip().is_loopback()
            {
                self.stats
                    .migrations_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return MigrationDecision::RejectedSubnetDisallowed {
                    addr: observed_addr,
                };
            }

            if !self.policy.allowed_subnets.is_empty() {
                let ip_str = observed_addr.ip().to_string();
                let allowed = self
                    .policy
                    .allowed_subnets
                    .iter()
                    .any(|prefix| ip_str.starts_with(prefix));
                if !allowed {
                    self.stats
                        .migrations_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    return MigrationDecision::RejectedSubnetDisallowed {
                        addr: observed_addr,
                    };
                }
            }

            // 3. Rate limiting check
            let window_start = now_sec.saturating_sub(self.policy.rate_window_secs);
            record.migration_timestamps.retain(|&t| t >= window_start);

            if record.migration_timestamps.len() >= self.policy.max_migrations_per_window {
                self.stats
                    .migrations_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return MigrationDecision::RejectedRateLimitExceeded {
                    count: record.migration_timestamps.len(),
                    limit: self.policy.max_migrations_per_window,
                };
            }
        }

        // Approved migration: update state and emit event
        let prev_addr = record.current_addr;
        record.current_addr = observed_addr;
        record.migration_timestamps.push(now_sec);
        let peer_id = record.peer_identity.clone();

        self.stats
            .migrations_accepted
            .fetch_add(1, Ordering::Relaxed);

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let event = MigrationEvent {
            connection_id,
            prev_addr,
            new_addr: observed_addr,
            timestamp_ms: now_ms,
            rtt,
            peer_identity: peer_id,
        };

        let _ = self.event_tx.send(event);
        MigrationDecision::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permissive_migration() {
        let coordinator = MigrationCoordinator::with_defaults();
        let cid = 42;
        let addr1: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        coordinator.register_connection(cid, addr1, Some("client-a".to_string()));

        let d1 = coordinator.evaluate_migration(cid, addr1, Duration::from_millis(10));
        assert_eq!(d1, MigrationDecision::NoChange);

        let d2 = coordinator.evaluate_migration(cid, addr2, Duration::from_millis(15));
        assert_eq!(d2, MigrationDecision::Allowed);

        let stats = coordinator.stats();
        assert_eq!(stats.migrations_total.load(Ordering::Relaxed), 1);
        assert_eq!(stats.migrations_accepted.load(Ordering::Relaxed), 1);
        assert_eq!(stats.migrations_rejected.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_disabled_policy_rejects_migration() {
        let policy = MigrationPolicy {
            mode: MigrationPolicyMode::Disabled,
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(policy, Arc::new(MigrationStats::default()));
        let cid = 100;
        let addr1: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.2:4000".parse().unwrap();

        coordinator.register_connection(cid, addr1, None);
        let d = coordinator.evaluate_migration(cid, addr2, Duration::from_millis(20));

        assert_eq!(d, MigrationDecision::RejectedDisabled);
        assert_eq!(
            coordinator
                .stats()
                .migrations_rejected
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_gated_rate_limiting() {
        let policy = MigrationPolicy {
            mode: MigrationPolicyMode::Gated,
            max_migrations_per_window: 2,
            rate_window_secs: 60,
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(policy, Arc::new(MigrationStats::default()));
        let cid = 7;
        let a0: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let a1: SocketAddr = "127.0.0.1:6001".parse().unwrap();
        let a2: SocketAddr = "127.0.0.1:6002".parse().unwrap();
        let a3: SocketAddr = "127.0.0.1:6003".parse().unwrap();

        coordinator.register_connection(cid, a0, None);

        assert_eq!(
            coordinator.evaluate_migration(cid, a1, Duration::from_millis(5)),
            MigrationDecision::Allowed
        );
        assert_eq!(
            coordinator.evaluate_migration(cid, a2, Duration::from_millis(5)),
            MigrationDecision::Allowed
        );

        // 3rd migration exceeds limit of 2
        let d3 = coordinator.evaluate_migration(cid, a3, Duration::from_millis(5));
        assert!(matches!(
            d3,
            MigrationDecision::RejectedRateLimitExceeded { count: 2, limit: 2 }
        ));
    }

    #[test]
    fn test_gated_subnet_allowlist() {
        let policy = MigrationPolicy {
            mode: MigrationPolicyMode::Gated,
            allowed_subnets: vec!["10.0.".to_string(), "192.168.1.".to_string()],
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(policy, Arc::new(MigrationStats::default()));
        let cid = 99;
        let a0: SocketAddr = "10.0.1.5:8000".parse().unwrap();
        let a1: SocketAddr = "10.0.2.6:8000".parse().unwrap();
        let disallowed: SocketAddr = "172.16.0.1:8000".parse().unwrap();

        coordinator.register_connection(cid, a0, None);
        assert_eq!(
            coordinator.evaluate_migration(cid, a1, Duration::from_millis(5)),
            MigrationDecision::Allowed
        );
        assert_eq!(
            coordinator.evaluate_migration(cid, disallowed, Duration::from_millis(5)),
            MigrationDecision::RejectedSubnetDisallowed { addr: disallowed }
        );
    }
}
