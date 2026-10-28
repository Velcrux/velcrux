//! Distributed Dynamic Content Router & Anycast Session Migration (`ADR-044`).
//!
//! Provides edge Point-of-Presence (PoP) topology tracking, latency/load-aware anycast
//! traffic steering, real-time route failover, and cryptographically verified live QUIC
//! session migration tickets across geographically distributed clusters.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;

/// Domain separator tag for cryptographic migration tickets.
pub const MIGRATION_TICKET_DOMAIN_TAG: &[u8] = b"velcrux-migration-ticket:v1";

/// Operating status of an edge Point-of-Presence (PoP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PopStatus {
    /// Fully healthy and accepting new routing requests and traffic.
    Healthy,
    /// Experiencing elevated latency or packet loss; traffic is deprioritized.
    Degraded,
    /// Undergoing maintenance; existing sessions complete but new routes are steered elsewhere.
    Draining,
    /// Offline or unreachable; completely excluded from anycast routing tables.
    Offline,
}

impl std::fmt::Display for PopStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PopStatus::Healthy => write!(f, "healthy"),
            PopStatus::Degraded => write!(f, "degraded"),
            PopStatus::Draining => write!(f, "draining"),
            PopStatus::Offline => write!(f, "offline"),
        }
    }
}

/// Real-time telemetry and network quality measurements for an edge PoP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopHealthMetrics {
    /// Measured round-trip latency to regional test probes in milliseconds.
    pub rtt_ms: f64,
    /// Jitter in milliseconds.
    pub jitter_ms: f64,
    /// Packet loss ratio (e.g. 0.001 = 0.1% loss).
    pub packet_loss_ratio: f64,
    /// Current CPU utilization ratio (0.0 to 1.0).
    pub cpu_utilization: f64,
    /// Current network bandwidth utilization ratio (0.0 to 1.0).
    pub bandwidth_utilization: f64,
    /// Total concurrent active client transfer sessions.
    pub active_connections: u64,
}

impl Default for PopHealthMetrics {
    fn default() -> Self {
        Self {
            rtt_ms: 15.0,
            jitter_ms: 1.2,
            packet_loss_ratio: 0.0001,
            cpu_utilization: 0.25,
            bandwidth_utilization: 0.30,
            active_connections: 0,
        }
    }
}

/// Node descriptor for a distributed edge Point-of-Presence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopNode {
    /// Unique identifier for the PoP (e.g. "pop-iad", "pop-lhr", "pop-nrt").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Geographic region (e.g. "us-east", "eu-west", "ap-northeast").
    pub region: String,
    /// Geographic latitude (degrees north).
    pub latitude: f64,
    /// Geographic longitude (degrees east).
    pub longitude: f64,
    /// Primary network listen address for QUIC data plane transfers.
    pub address: SocketAddr,
    /// Operational status of the PoP.
    pub status: PopStatus,
    /// Maximum link capacity in bits per second.
    pub capacity_bps: u64,
    /// Current egress load in bits per second.
    pub current_load_bps: u64,
    /// Real-time health metrics.
    pub metrics: PopHealthMetrics,
    /// Multiplier weighting network transit costs (1.0 = baseline, >1.0 = expensive).
    pub cost_multiplier: f64,
}

impl PopNode {
    /// Returns true if this PoP is admissible to accept new traffic.
    pub fn is_admissible(&self, required_bps: u64) -> bool {
        if self.status != PopStatus::Healthy && self.status != PopStatus::Degraded {
            return false;
        }
        let available_bps = self.capacity_bps.saturating_sub(self.current_load_bps);
        available_bps >= required_bps
    }

    /// Computes a composite routing score (lower is better).
    /// Incorporates great-circle distance, measured RTT, packet loss, and load penalty.
    pub fn composite_score(&self, client_lat: f64, client_lon: f64, required_bps: u64) -> f64 {
        if !self.is_admissible(required_bps) {
            return f64::MAX;
        }

        let distance_km =
            haversine_distance_km(client_lat, client_lon, self.latitude, self.longitude);
        let dist_score = distance_km * 0.05; // 1,000 km ≈ 50 ms virtual RTT
        let rtt_score = self.metrics.rtt_ms;
        let loss_penalty = self.metrics.packet_loss_ratio * 1000.0 * 20.0;
        let load_ratio = self.current_load_bps as f64 / self.capacity_bps.max(1) as f64;
        let load_penalty = (load_ratio / (1.0 - load_ratio).max(0.01)) * 10.0;
        let status_penalty = match self.status {
            PopStatus::Healthy => 0.0,
            PopStatus::Degraded => 50.0,
            PopStatus::Draining => 10_000.0,
            PopStatus::Offline => f64::MAX,
        };

        (dist_score + rtt_score + loss_penalty + load_penalty + status_penalty)
            * self.cost_multiplier
    }
}

/// Great-circle distance between two geographic coordinates using Haversine formula.
pub fn haversine_distance_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;

    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();

    let a =
        (d_lat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_KM * c
}

/// Request for selecting the optimal edge PoP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRequest {
    /// Client identifier or IP address string.
    pub client_id: String,
    /// Client geographic latitude.
    pub latitude: f64,
    /// Client geographic longitude.
    pub longitude: f64,
    /// Optional preferred region hint.
    pub preferred_region: Option<String>,
    /// Estimated bandwidth requirement for the transfer in bits per second.
    pub required_bandwidth_bps: u64,
    /// Optional session affinity token for existing connections.
    pub affinity_token: Option<String>,
}

/// Authoritative routing decision produced by the Anycast Router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    /// Client identifier routed.
    pub client_id: String,
    /// Selected PoP identifier.
    pub selected_pop_id: String,
    /// Target socket address for QUIC data plane connection.
    pub pop_address: SocketAddr,
    /// Target PoP region.
    pub pop_region: String,
    /// Estimated round-trip latency to the selected PoP in milliseconds.
    pub estimated_rtt_ms: f64,
    /// Geographic distance in kilometers.
    pub distance_km: f64,
    /// Calculated composite routing cost score.
    pub composite_score: f64,
    /// Failover count considered during route calculation.
    pub failover_count: usize,
    /// Whether migration from previous PoP is recommended.
    pub migration_recommended: bool,
    /// Rationale for routing decision.
    pub reason: String,
}

/// Cryptographically signed handover ticket authorizing session migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationTicket {
    /// Unique migration ticket identifier.
    pub ticket_id: String,
    /// Active session identifier being migrated.
    pub session_id: String,
    /// Associated transfer identifier.
    pub transfer_id: String,
    /// Source PoP identifier handing off traffic.
    pub source_pop_id: String,
    /// Target PoP identifier assuming responsibility.
    pub target_pop_id: String,
    /// Target PoP socket address.
    pub target_address: SocketAddr,
    /// Bytes acknowledged and checkpointed prior to migration.
    pub bytes_committed: u64,
    /// Total bytes in the transfer.
    pub total_bytes: u64,
    /// Chunk offset index where the new PoP should resume streaming.
    pub chunk_offset: u64,
    /// Unix epoch timestamp in seconds when the ticket was issued.
    pub issued_at_secs: u64,
    /// Unix epoch timestamp in seconds when the ticket expires.
    pub expires_at_secs: u64,
    /// BLAKE3 keyed authentication MAC.
    #[serde(with = "hex_bytes_32")]
    pub signature_mac: [u8; 32],
}

impl MigrationTicket {
    /// Computes the authentication MAC for ticket validation.
    pub fn compute_mac(&self, secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(secret);
        hasher.update(MIGRATION_TICKET_DOMAIN_TAG);
        hasher.update(self.ticket_id.as_bytes());
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.transfer_id.as_bytes());
        hasher.update(self.source_pop_id.as_bytes());
        hasher.update(self.target_pop_id.as_bytes());
        let addr_str = self.target_address.to_string();
        hasher.update(addr_str.as_bytes());
        hasher.update(&self.bytes_committed.to_le_bytes());
        hasher.update(&self.total_bytes.to_le_bytes());
        hasher.update(&self.chunk_offset.to_le_bytes());
        hasher.update(&self.issued_at_secs.to_le_bytes());
        hasher.update(&self.expires_at_secs.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verifies ticket integrity, authenticity, and expiration.
    pub fn verify(&self, secret: &[u8; 32], now_secs: u64) -> bool {
        if now_secs > self.expires_at_secs {
            return false;
        }
        let expected = self.compute_mac(secret);
        self.signature_mac == expected
    }
}

/// State of an active session migration handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    /// Ticket issued and migration initiated.
    Initiated,
    /// Inflight stream frames pausing on source PoP; target PoP preparing checkpoint.
    HandingOff,
    /// Migration committed; target PoP resumed active data streaming.
    Committed,
    /// Migration failed due to timeout or network drop; source PoP resumes.
    Failed,
}

impl std::fmt::Display for MigrationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationState::Initiated => write!(f, "initiated"),
            MigrationState::HandingOff => write!(f, "handing_off"),
            MigrationState::Committed => write!(f, "committed"),
            MigrationState::Failed => write!(f, "failed"),
        }
    }
}

/// Detailed audit record of an executed session migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMigrationRecord {
    pub session_id: String,
    pub transfer_id: String,
    pub source_pop_id: String,
    pub target_pop_id: String,
    pub state: MigrationState,
    pub handover_latency_us: u64,
    pub resumed_offset: u64,
    pub total_bytes: u64,
    pub started_at_secs: u64,
    pub completed_at_secs: Option<u64>,
}

/// Comprehensive status summary of the Anycast Router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterStatus {
    pub total_pops: usize,
    pub healthy_pops: usize,
    pub degraded_pops: usize,
    pub draining_pops: usize,
    pub offline_pops: usize,
    pub total_routes_computed: u64,
    pub total_migrations_committed: u64,
    pub total_migration_failures: u64,
    pub active_migrations: usize,
}

/// Core Anycast Content Router and Session Migration Coordinator.
pub struct AnycastRouter {
    pops: RwLock<HashMap<String, PopNode>>,
    secret_key: [u8; 32],
    migrations: RwLock<HashMap<String, SessionMigrationRecord>>,
    routes_computed: AtomicU64,
    migrations_committed: AtomicU64,
    migration_failures: AtomicU64,
}

impl AnycastRouter {
    /// Creates a new AnycastRouter with a cryptographic secret key for migration tickets.
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self {
            pops: RwLock::new(HashMap::new()),
            secret_key,
            migrations: RwLock::new(HashMap::new()),
            routes_computed: AtomicU64::new(0),
            migrations_committed: AtomicU64::new(0),
            migration_failures: AtomicU64::new(0),
        }
    }

    /// Registers or updates an edge PoP node in the routing registry.
    pub fn register_pop(&self, pop: PopNode) {
        let mut pops = self.pops.write().unwrap();
        pops.insert(pop.id.clone(), pop);
    }

    /// Updates operational health and measured quality metrics for a PoP.
    pub fn update_pop_health(
        &self,
        pop_id: &str,
        status: PopStatus,
        metrics: PopHealthMetrics,
    ) -> Result<(), VelcruxError> {
        let mut pops = self.pops.write().unwrap();
        if let Some(pop) = pops.get_mut(pop_id) {
            pop.status = status;
            pop.metrics = metrics;
            Ok(())
        } else {
            Err(VelcruxError::Config(format!("PoP '{}' not found", pop_id)))
        }
    }

    /// Transitions a PoP into draining mode (gracefully migrating sessions).
    pub fn drain_pop(&self, pop_id: &str) -> Result<(), VelcruxError> {
        let mut pops = self.pops.write().unwrap();
        if let Some(pop) = pops.get_mut(pop_id) {
            pop.status = PopStatus::Draining;
            Ok(())
        } else {
            Err(VelcruxError::Config(format!("PoP '{}' not found", pop_id)))
        }
    }

    /// Retrieves an individual PoP descriptor if registered.
    pub fn get_pop(&self, pop_id: &str) -> Option<PopNode> {
        let pops = self.pops.read().unwrap();
        pops.get(pop_id).cloned()
    }

    /// Lists all registered edge PoP nodes.
    pub fn list_pops(&self) -> Vec<PopNode> {
        let pops = self.pops.read().unwrap();
        pops.values().cloned().collect()
    }

    /// Resolves the optimal edge PoP for an incoming client transfer request.
    pub fn compute_route(&self, req: &RouteRequest) -> Result<RouteDecision, VelcruxError> {
        let pops = self.pops.read().unwrap();
        if pops.is_empty() {
            return Err(VelcruxError::Config(
                "no edge PoPs registered in router".to_string(),
            ));
        }

        let mut best_pop: Option<(&PopNode, f64, f64)> = None;
        let mut failover_count = 0;

        for pop in pops.values() {
            if !pop.is_admissible(req.required_bandwidth_bps) {
                failover_count += 1;
                continue;
            }

            let score =
                pop.composite_score(req.latitude, req.longitude, req.required_bandwidth_bps);
            let distance =
                haversine_distance_km(req.latitude, req.longitude, pop.latitude, pop.longitude);

            match best_pop {
                None => best_pop = Some((pop, score, distance)),
                Some((_, best_score, _)) if score < best_score => {
                    best_pop = Some((pop, score, distance));
                }
                _ => {}
            }
        }

        let (chosen_pop, score, distance) = match best_pop {
            Some(p) => p,
            None => {
                // If no admissible PoP satisfies strict capacity, find any non-offline PoP
                let mut fallback = None;
                for pop in pops.values() {
                    if pop.status != PopStatus::Offline {
                        let d = haversine_distance_km(
                            req.latitude,
                            req.longitude,
                            pop.latitude,
                            pop.longitude,
                        );
                        fallback = Some((pop, 9999.0, d));
                        break;
                    }
                }
                fallback.ok_or_else(|| {
                    VelcruxError::Config("all registered edge PoPs are offline".to_string())
                })?
            }
        };

        self.routes_computed.fetch_add(1, Ordering::Relaxed);

        let rtt = chosen_pop.metrics.rtt_ms + (distance * 0.02);
        let decision = RouteDecision {
            client_id: req.client_id.clone(),
            selected_pop_id: chosen_pop.id.clone(),
            pop_address: chosen_pop.address,
            pop_region: chosen_pop.region.clone(),
            estimated_rtt_ms: rtt,
            distance_km: distance,
            composite_score: score,
            failover_count,
            migration_recommended: chosen_pop.status == PopStatus::Degraded,
            reason: format!(
                "Optimal route selected: {} ({} ms estimated RTT, {:.1} km distance)",
                chosen_pop.id, rtt as u64, distance
            ),
        };

        Ok(decision)
    }

    /// Issues a cryptographically signed migration ticket authorizing transfer handover.
    pub fn issue_migration_ticket(
        &self,
        session_id: &str,
        transfer_id: &str,
        source_pop_id: &str,
        target_pop_id: &str,
        bytes_committed: u64,
        total_bytes: u64,
        chunk_offset: u64,
        ttl_secs: u64,
        now_secs: u64,
    ) -> Result<MigrationTicket, VelcruxError> {
        let pops = self.pops.read().unwrap();
        let target_pop = pops.get(target_pop_id).ok_or_else(|| {
            VelcruxError::Config(format!("target PoP '{}' does not exist", target_pop_id))
        })?;

        if target_pop.status == PopStatus::Offline {
            return Err(VelcruxError::Config(format!(
                "target PoP '{}' is offline",
                target_pop_id
            )));
        }

        let ticket_id = format!("tkt-{}-{:08x}", session_id, now_secs % 1000000);

        let mut ticket = MigrationTicket {
            ticket_id,
            session_id: session_id.to_string(),
            transfer_id: transfer_id.to_string(),
            source_pop_id: source_pop_id.to_string(),
            target_pop_id: target_pop_id.to_string(),
            target_address: target_pop.address,
            bytes_committed,
            total_bytes,
            chunk_offset,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + ttl_secs,
            signature_mac: [0u8; 32],
        };

        ticket.signature_mac = ticket.compute_mac(&self.secret_key);

        let record = SessionMigrationRecord {
            session_id: session_id.to_string(),
            transfer_id: transfer_id.to_string(),
            source_pop_id: source_pop_id.to_string(),
            target_pop_id: target_pop_id.to_string(),
            state: MigrationState::Initiated,
            handover_latency_us: 0,
            resumed_offset: chunk_offset,
            total_bytes,
            started_at_secs: now_secs,
            completed_at_secs: None,
        };

        let mut migrations = self.migrations.write().unwrap();
        migrations.insert(session_id.to_string(), record);

        Ok(ticket)
    }

    /// Verifies and executes the live migration handover at the target PoP.
    pub fn execute_migration_handover(
        &self,
        ticket: &MigrationTicket,
        now_secs: u64,
    ) -> Result<SessionMigrationRecord, VelcruxError> {
        let handover_start = Instant::now();

        if !ticket.verify(&self.secret_key, now_secs) {
            self.migration_failures.fetch_add(1, Ordering::Relaxed);
            return Err(VelcruxError::Config(
                "invalid, tampered, or expired migration ticket".to_string(),
            ));
        }

        let handover_elapsed_us = handover_start.elapsed().as_micros() as u64;

        let mut migrations = self.migrations.write().unwrap();
        let record = migrations
            .entry(ticket.session_id.clone())
            .or_insert_with(|| SessionMigrationRecord {
                session_id: ticket.session_id.clone(),
                transfer_id: ticket.transfer_id.clone(),
                source_pop_id: ticket.source_pop_id.clone(),
                target_pop_id: ticket.target_pop_id.clone(),
                state: MigrationState::HandingOff,
                handover_latency_us: handover_elapsed_us,
                resumed_offset: ticket.chunk_offset,
                total_bytes: ticket.total_bytes,
                started_at_secs: ticket.issued_at_secs,
                completed_at_secs: None,
            });

        record.state = MigrationState::Committed;
        record.completed_at_secs = Some(now_secs);
        record.handover_latency_us = handover_elapsed_us;

        self.migrations_committed.fetch_add(1, Ordering::Relaxed);

        Ok(record.clone())
    }

    /// Generates an operational status report of the router.
    pub fn status(&self) -> RouterStatus {
        let pops = self.pops.read().unwrap();
        let mut healthy = 0;
        let mut degraded = 0;
        let mut draining = 0;
        let mut offline = 0;

        for pop in pops.values() {
            match pop.status {
                PopStatus::Healthy => healthy += 1,
                PopStatus::Degraded => degraded += 1,
                PopStatus::Draining => draining += 1,
                PopStatus::Offline => offline += 1,
            }
        }

        let migrations = self.migrations.read().unwrap();
        let active_m = migrations
            .values()
            .filter(|m| {
                m.state == MigrationState::Initiated || m.state == MigrationState::HandingOff
            })
            .count();

        RouterStatus {
            total_pops: pops.len(),
            healthy_pops: healthy,
            degraded_pops: degraded,
            draining_pops: draining,
            offline_pops: offline,
            total_routes_computed: self.routes_computed.load(Ordering::Relaxed),
            total_migrations_committed: self.migrations_committed.load(Ordering::Relaxed),
            total_migration_failures: self.migration_failures.load(Ordering::Relaxed),
            active_migrations: active_m,
        }
    }
}

/// Serde helper for serializing/deserializing `[u8; 32]` as hex string.
pub mod hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            let byte_str = &s[i * 2..i * 2 + 2];
            out[i] = u8::from_str_radix(byte_str, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

/// Benchmark evaluation report for Anycast routing and session migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterBenchmarkReport {
    pub pop_count: usize,
    pub routes_evaluated: usize,
    pub routing_throughput_routes_per_sec: f64,
    pub avg_route_latency_us: f64,
    pub migration_cycles_evaluated: usize,
    pub migration_throughput_per_sec: f64,
    pub avg_migration_handover_latency_us: f64,
    pub all_migrations_verified: bool,
    pub failover_convergence_latency_ms: f64,
}

/// Executes simulated routing and session migration benchmark evaluating throughput and failover latency.
pub fn run_router_benchmark(pop_count: usize, iterations: usize) -> RouterBenchmarkReport {
    let router = AnycastRouter::new([0x42; 32]);
    let pops_to_create = pop_count.max(2);
    let sample_iterations = iterations.max(10);

    // Populate simulated global PoPs
    for i in 0..pops_to_create {
        let lat = -60.0 + (120.0 * (i as f64 / pops_to_create as f64));
        let lon = -150.0 + (300.0 * (i as f64 / pops_to_create as f64));
        let pop = PopNode {
            id: format!("pop-{:02}", i),
            name: format!("Edge PoP {:02}", i),
            region: format!("region-{:02}", i % 4),
            latitude: lat,
            longitude: lon,
            address: format!("10.0.{}.1:7443", i + 1).parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000, // 10 Gbps
            current_load_bps: 1_000_000_000 * (i as u64 % 5),
            metrics: PopHealthMetrics {
                rtt_ms: 5.0 + (i as f64 * 3.0),
                jitter_ms: 1.0,
                packet_loss_ratio: 0.0001,
                cpu_utilization: 0.20,
                bandwidth_utilization: 0.25,
                active_connections: 50,
            },
            cost_multiplier: 1.0,
        };
        router.register_pop(pop);
    }

    // 1. Measure route calculation throughput
    let route_start = Instant::now();
    for i in 0..sample_iterations {
        let req = RouteRequest {
            client_id: format!("client-bench-{}", i),
            latitude: 37.7749 + (i as f64 * 0.01),
            longitude: -122.4194 + (i as f64 * 0.01),
            preferred_region: None,
            required_bandwidth_bps: 100_000_000,
            affinity_token: None,
        };
        let _ = router.compute_route(&req).expect("route calculation");
    }
    let route_elapsed = route_start.elapsed();
    let routing_throughput = sample_iterations as f64 / route_elapsed.as_secs_f64().max(1e-9);
    let avg_route_latency_us =
        (route_elapsed.as_secs_f64() * 1_000_000.0) / sample_iterations as f64;

    // 2. Measure failover convergence
    let failover_start = Instant::now();
    router.drain_pop("pop-00").ok();
    let failover_req = RouteRequest {
        client_id: "client-failover".to_string(),
        latitude: -60.0,
        longitude: -150.0,
        preferred_region: None,
        required_bandwidth_bps: 50_000_000,
        affinity_token: None,
    };
    let failover_decision = router.compute_route(&failover_req).expect("failover route");
    assert_ne!(failover_decision.selected_pop_id, "pop-00");
    let failover_convergence_ms = failover_start.elapsed().as_secs_f64() * 1000.0;

    // 3. Measure session migration ticket issuance and handover
    let mig_start = Instant::now();
    let mut all_verified = true;
    let mig_count = sample_iterations.min(500);

    for i in 0..mig_count {
        let session_id = format!("sess-bench-{}", i);
        let ticket = router
            .issue_migration_ticket(
                &session_id,
                "xfer-01",
                "pop-00",
                "pop-01",
                1048576 * (i as u64 + 1),
                104857600,
                10 * (i as u64 + 1),
                300,
                1793130000 + i as u64,
            )
            .expect("issue ticket");

        let handover = router
            .execute_migration_handover(&ticket, 1793130001 + i as u64)
            .expect("handover");

        if handover.state != MigrationState::Committed {
            all_verified = false;
        }
    }

    let mig_elapsed = mig_start.elapsed();
    let migration_throughput = mig_count as f64 / mig_elapsed.as_secs_f64().max(1e-9);
    let avg_handover_latency_us = (mig_elapsed.as_secs_f64() * 1_000_000.0) / mig_count as f64;

    RouterBenchmarkReport {
        pop_count: pops_to_create,
        routes_evaluated: sample_iterations,
        routing_throughput_routes_per_sec: routing_throughput,
        avg_route_latency_us,
        migration_cycles_evaluated: mig_count,
        migration_throughput_per_sec: migration_throughput,
        avg_migration_handover_latency_us: avg_handover_latency_us,
        all_migrations_verified: all_verified,
        failover_convergence_latency_ms: failover_convergence_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop_registration_and_status() {
        let router = AnycastRouter::new([1u8; 32]);
        assert_eq!(router.list_pops().len(), 0);

        let pop1 = PopNode {
            id: "pop-iad".to_string(),
            name: "US East (Ashburn)".to_string(),
            region: "us-east".to_string(),
            latitude: 39.0438,
            longitude: -77.4874,
            address: "198.51.100.1:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 2_000_000_000,
            metrics: PopHealthMetrics::default(),
            cost_multiplier: 1.0,
        };
        router.register_pop(pop1.clone());

        assert_eq!(router.list_pops().len(), 1);
        let fetched = router.get_pop("pop-iad").expect("pop exists");
        assert_eq!(fetched.name, "US East (Ashburn)");
        assert_eq!(fetched.status, PopStatus::Healthy);

        let status = router.status();
        assert_eq!(status.total_pops, 1);
        assert_eq!(status.healthy_pops, 1);
        assert_eq!(status.draining_pops, 0);
    }

    #[test]
    fn test_optimal_route_selection() {
        let router = AnycastRouter::new([2u8; 32]);

        let pop_ny = PopNode {
            id: "pop-nyc".to_string(),
            name: "New York".to_string(),
            region: "us-east".to_string(),
            latitude: 40.7128,
            longitude: -74.0060,
            address: "198.51.100.1:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 1_000_000_000,
            metrics: PopHealthMetrics {
                rtt_ms: 10.0,
                ..Default::default()
            },
            cost_multiplier: 1.0,
        };

        let pop_sf = PopNode {
            id: "pop-sfo".to_string(),
            name: "San Francisco".to_string(),
            region: "us-west".to_string(),
            latitude: 37.7749,
            longitude: -122.4194,
            address: "198.51.100.2:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 1_000_000_000,
            metrics: PopHealthMetrics {
                rtt_ms: 12.0,
                ..Default::default()
            },
            cost_multiplier: 1.0,
        };

        router.register_pop(pop_ny);
        router.register_pop(pop_sf);

        // Client in Boston (close to NYC)
        let req_boston = RouteRequest {
            client_id: "client-boston".to_string(),
            latitude: 42.3601,
            longitude: -71.0589,
            preferred_region: None,
            required_bandwidth_bps: 50_000_000,
            affinity_token: None,
        };
        let decision_boston = router.compute_route(&req_boston).expect("route boston");
        assert_eq!(decision_boston.selected_pop_id, "pop-nyc");

        // Client in Seattle (close to SFO)
        let req_seattle = RouteRequest {
            client_id: "client-seattle".to_string(),
            latitude: 47.6062,
            longitude: -122.3321,
            preferred_region: None,
            required_bandwidth_bps: 50_000_000,
            affinity_token: None,
        };
        let decision_seattle = router.compute_route(&req_seattle).expect("route seattle");
        assert_eq!(decision_seattle.selected_pop_id, "pop-sfo");
    }

    #[test]
    fn test_pop_drain_and_automatic_failover() {
        let router = AnycastRouter::new([3u8; 32]);

        let pop_primary = PopNode {
            id: "pop-primary".to_string(),
            name: "Primary PoP".to_string(),
            region: "us-east".to_string(),
            latitude: 38.0,
            longitude: -77.0,
            address: "198.51.100.1:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 1_000_000_000,
            metrics: PopHealthMetrics {
                rtt_ms: 5.0,
                ..Default::default()
            },
            cost_multiplier: 1.0,
        };

        let pop_backup = PopNode {
            id: "pop-backup".to_string(),
            name: "Backup PoP".to_string(),
            region: "us-east".to_string(),
            latitude: 39.0,
            longitude: -76.0,
            address: "198.51.100.2:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 1_000_000_000,
            metrics: PopHealthMetrics {
                rtt_ms: 15.0,
                ..Default::default()
            },
            cost_multiplier: 1.0,
        };

        router.register_pop(pop_primary);
        router.register_pop(pop_backup);

        let req = RouteRequest {
            client_id: "client-dc".to_string(),
            latitude: 38.9,
            longitude: -77.0,
            preferred_region: None,
            required_bandwidth_bps: 100_000_000,
            affinity_token: None,
        };

        // Before drain: routes to pop-primary
        let d1 = router.compute_route(&req).expect("route before drain");
        assert_eq!(d1.selected_pop_id, "pop-primary");

        // Drain pop-primary
        router.drain_pop("pop-primary").expect("drain primary");

        // After drain: automatically fails over to pop-backup
        let d2 = router.compute_route(&req).expect("route after drain");
        assert_eq!(d2.selected_pop_id, "pop-backup");
    }

    #[test]
    fn test_migration_ticket_issuance_and_tamper_rejection() {
        let secret = [0x55u8; 32];
        let router = AnycastRouter::new(secret);

        let pop_target = PopNode {
            id: "pop-target".to_string(),
            name: "Target PoP".to_string(),
            region: "eu-west".to_string(),
            latitude: 51.5074,
            longitude: -0.1278,
            address: "198.51.100.10:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 500_000_000,
            metrics: PopHealthMetrics::default(),
            cost_multiplier: 1.0,
        };
        router.register_pop(pop_target);

        let now = 1793130000;
        let mut ticket = router
            .issue_migration_ticket(
                "sess-99",
                "xfer-42",
                "pop-source",
                "pop-target",
                5242880,
                10485760,
                5,
                60,
                now,
            )
            .expect("issue ticket");

        // 1. Valid ticket must verify
        assert!(ticket.verify(&secret, now + 10));

        // 2. Expired ticket must fail
        assert!(!ticket.verify(&secret, now + 61));

        // 3. Tampered bytes must fail
        ticket.bytes_committed += 1;
        assert!(!ticket.verify(&secret, now + 10));
        ticket.bytes_committed -= 1; // restore

        // 4. Tampered MAC must fail
        ticket.signature_mac[0] ^= 0xFF;
        assert!(!ticket.verify(&secret, now + 10));
    }

    #[test]
    fn test_session_migration_handover_execution() {
        let secret = [0x77u8; 32];
        let router = AnycastRouter::new(secret);

        let pop_dst = PopNode {
            id: "pop-dst".to_string(),
            name: "Destination PoP".to_string(),
            region: "ap-south".to_string(),
            latitude: 19.0760,
            longitude: 72.8777,
            address: "198.51.100.20:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 1_000_000_000,
            metrics: PopHealthMetrics::default(),
            cost_multiplier: 1.0,
        };
        router.register_pop(pop_dst);

        let now = 1793130100;
        let ticket = router
            .issue_migration_ticket(
                "sess-alpha",
                "xfer-omega",
                "pop-src",
                "pop-dst",
                1048576,
                2097152,
                1,
                120,
                now,
            )
            .expect("issue ticket");

        let handover = router
            .execute_migration_handover(&ticket, now + 5)
            .expect("handover executed");

        assert_eq!(handover.session_id, "sess-alpha");
        assert_eq!(handover.state, MigrationState::Committed);
        assert_eq!(handover.resumed_offset, 1);
        assert_eq!(handover.completed_at_secs, Some(now + 5));

        let status = router.status();
        assert_eq!(status.total_migrations_committed, 1);
        assert_eq!(status.total_migration_failures, 0);
    }

    #[test]
    fn test_router_benchmark_execution() {
        let report = run_router_benchmark(5, 20);
        assert_eq!(report.pop_count, 5);
        assert_eq!(report.routes_evaluated, 20);
        assert!(report.all_migrations_verified);
        assert!(report.routing_throughput_routes_per_sec > 0.0);
        assert!(report.migration_throughput_per_sec > 0.0);
        assert!(report.failover_convergence_latency_ms >= 0.0);
    }
}
