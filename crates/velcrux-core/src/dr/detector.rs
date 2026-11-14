//! Decentralized Multi-Path Health Probing & Failure Detection Engine (ADR-080).
//!
//! Provides dynamic failure detection tracking heartbeat intervals, jitter bounds,
//! multi-path probing (e.g. primary WAN, secondary WAN, witness relay), and statistical
//! suspicion scoring to differentiate transient hiccups from total regional network partitions.

use std::collections::{HashMap, VecDeque};

use super::types::{DrFailureDetectorConfig, HeartbeatMsg, ProbeHealthStatus};

/// Internal telemetry record tracking heartbeats and latency history for a peer cluster.
#[derive(Debug, Clone)]
struct PeerRecord {
    last_heartbeat_ms: u64,
    last_rpo_lag_ms: u64,
    intervals: VecDeque<u64>,
    /// Path ID -> last probe timestamp in ms (for multi-path probing).
    path_probes: HashMap<String, u64>,
}

impl PeerRecord {
    fn new(first_seen_ms: u64) -> Self {
        Self {
            last_heartbeat_ms: first_seen_ms,
            last_rpo_lag_ms: 0,
            intervals: VecDeque::new(),
            path_probes: HashMap::new(),
        }
    }

    fn record_interval(&mut self, interval_ms: u64, max_window: usize) {
        if self.intervals.len() >= max_window {
            self.intervals.pop_front();
        }
        self.intervals.push_back(interval_ms);
    }

    fn mean_interval(&self, fallback: f64) -> f64 {
        if self.intervals.is_empty() {
            return fallback;
        }
        let sum: u64 = self.intervals.iter().copied().sum();
        sum as f64 / self.intervals.len() as f64
    }

    fn jitter(&self, fallback: f64) -> f64 {
        if self.intervals.len() < 2 {
            return fallback;
        }
        let mean = self.mean_interval(fallback);
        let variance: f64 = self
            .intervals
            .iter()
            .map(|&intv| {
                let diff = intv as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / self.intervals.len() as f64;
        variance.sqrt()
    }
}

/// Dynamic health probing and failure detection engine.
#[derive(Debug, Clone)]
pub struct DrFailureDetector {
    config: DrFailureDetectorConfig,
    peers: HashMap<String, PeerRecord>,
}

impl DrFailureDetector {
    /// Create a new failure detector with the specified configuration.
    #[must_use]
    pub fn new(config: DrFailureDetectorConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// Access configuration.
    #[must_use]
    pub fn config(&self) -> &DrFailureDetectorConfig {
        &self.config
    }

    /// Register or update heartbeat observation from a remote cluster region.
    pub fn record_heartbeat(&mut self, msg: &HeartbeatMsg, arrival_time_ms: u64) {
        let max_window = self.config.history_window_size;
        let entry = self
            .peers
            .entry(msg.sender_cluster.clone())
            .or_insert_with(|| PeerRecord::new(arrival_time_ms));

        if entry.last_heartbeat_ms > 0 && arrival_time_ms > entry.last_heartbeat_ms {
            let interval = arrival_time_ms.saturating_sub(entry.last_heartbeat_ms);
            entry.record_interval(interval, max_window);
        }

        entry.last_heartbeat_ms = arrival_time_ms;
        entry.last_rpo_lag_ms = msg.rpo_lag_ms;

        // Default primary WAN path probe update
        entry
            .path_probes
            .insert("primary_wan".to_string(), arrival_time_ms);
    }

    /// Record a multi-path probe from an alternative transport route (e.g. secondary WAN or witness relay).
    pub fn record_path_probe(&mut self, cluster_id: &str, path_id: &str, probe_time_ms: u64) {
        let entry = self
            .peers
            .entry(cluster_id.to_string())
            .or_insert_with(|| PeerRecord::new(probe_time_ms));

        entry.path_probes.insert(path_id.to_string(), probe_time_ms);
    }

    /// Compute failure suspicion score for a cluster region in range [0.0, 1.0].
    ///
    /// 0.0 indicates full health, 1.0 indicates definite unreachable status.
    #[must_use]
    pub fn compute_suspicion_score(&self, cluster_id: &str, now_ms: u64) -> f64 {
        let Some(peer) = self.peers.get(cluster_id) else {
            return 1.0; // Unknown cluster is considered non-responsive
        };

        if peer.last_heartbeat_ms == 0 || now_ms <= peer.last_heartbeat_ms {
            return 0.0;
        }

        let elapsed = now_ms.saturating_sub(peer.last_heartbeat_ms);
        let expected_interval = peer.mean_interval(self.config.heartbeat_interval_ms as f64);
        let jitter = peer.jitter(self.config.jitter_bound_ms as f64);

        let threshold_ms = expected_interval + jitter;
        if elapsed as f64 <= threshold_ms {
            // Heartbeat within expected arrival + jitter window
            0.0
        } else {
            // Suspicion scales exponentially with time elapsed beyond acceptable jitter
            let extra = (elapsed as f64) - threshold_ms;
            let denominator = (self.config.heartbeat_interval_ms as f64)
                * (self.config.consecutive_loss_threshold as f64);
            let score = (extra / denominator).clamp(0.0, 1.0);
            score
        }
    }

    /// Determine health status for a cluster region at `now_ms`.
    #[must_use]
    pub fn check_health(&self, cluster_id: &str, now_ms: u64) -> ProbeHealthStatus {
        let Some(peer) = self.peers.get(cluster_id) else {
            return ProbeHealthStatus::Dead;
        };

        let elapsed = now_ms.saturating_sub(peer.last_heartbeat_ms);
        let allowed_grace = self.config.heartbeat_interval_ms + self.config.jitter_bound_ms;

        let missed_heartbeats = if elapsed <= allowed_grace {
            0
        } else {
            let overdue = elapsed - allowed_grace;
            1 + (overdue / self.config.heartbeat_interval_ms.max(1)) as u32
        };

        if missed_heartbeats >= self.config.consecutive_loss_threshold {
            ProbeHealthStatus::Dead
        } else {
            let suspicion = self.compute_suspicion_score(cluster_id, now_ms);
            if suspicion >= self.config.suspicion_threshold || missed_heartbeats >= 1 {
                ProbeHealthStatus::Suspect
            } else {
                ProbeHealthStatus::Alive
            }
        }
    }

    /// Differentiate transient multi-path degradation from a total regional partition.
    ///
    /// Returns `true` if ALL registered probe paths for the cluster have timed out.
    /// Returns `false` if at least one alternative path (e.g. secondary WAN or witness relay) is still responsive.
    #[must_use]
    pub fn is_total_network_partition(&self, cluster_id: &str, now_ms: u64) -> bool {
        let Some(peer) = self.peers.get(cluster_id) else {
            return true;
        };

        if peer.path_probes.is_empty() {
            return self.check_health(cluster_id, now_ms) == ProbeHealthStatus::Dead;
        }

        let timeout_ms =
            self.config.heartbeat_interval_ms * self.config.consecutive_loss_threshold as u64;
        // If all paths have timed out, it's a total network partition
        peer.path_probes
            .values()
            .all(|&probe_ms| now_ms.saturating_sub(probe_ms) >= timeout_ms)
    }

    /// Retrieve detailed telemetry stats for a peer: (avg_interval_ms, jitter_ms, consecutive_missed, suspicion_score, last_rpo_lag_ms).
    #[must_use]
    pub fn peer_telemetry(
        &self,
        cluster_id: &str,
        now_ms: u64,
    ) -> Option<(f64, f64, u32, f64, u64)> {
        let peer = self.peers.get(cluster_id)?;
        let avg_intv = peer.mean_interval(self.config.heartbeat_interval_ms as f64);
        let jitter = peer.jitter(self.config.jitter_bound_ms as f64);
        let elapsed = now_ms.saturating_sub(peer.last_heartbeat_ms);
        let missed = (elapsed / self.config.heartbeat_interval_ms.max(1)) as u32;
        let suspicion = self.compute_suspicion_score(cluster_id, now_ms);
        let rpo = peer.last_rpo_lag_ms;

        Some((avg_intv, jitter, missed, suspicion, rpo))
    }

    /// Retrieve the last observed RPO replication lag for a cluster.
    #[must_use]
    pub fn last_rpo_lag_ms(&self, cluster_id: &str) -> u64 {
        self.peers
            .get(cluster_id)
            .map(|p| p.last_rpo_lag_ms)
            .unwrap_or(0)
    }
}
