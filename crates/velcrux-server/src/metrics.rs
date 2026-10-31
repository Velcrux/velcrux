//! Prometheus metrics exporter HTTP server (`OPERATIONS.md` §7).
//!
//! Exposes `/metrics` in standard Prometheus text format (`0.0.4`), `/healthz` & `/livez`
//! for Kubernetes/systemd liveness probes, and `/readyz` for readiness validation
//! on the configured `telemetry.metrics_listen` address.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::oneshot;
use velcrux_core::session::ServerStats;

/// Safely sample process CPU time (in seconds) and resident memory (in bytes)
/// without requiring unsafe code.
fn sample_process_metrics() -> (f64, u64) {
    #[cfg(target_os = "linux")]
    {
        let mut cpu_secs = 0.0;
        let mut rss_bytes = 0u64;

        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
            let fields: Vec<&str> = stat.split_whitespace().collect();
            if fields.len() > 14 {
                let utime: f64 = fields[13].parse().unwrap_or(0.0);
                let stime: f64 = fields[14].parse().unwrap_or(0.0);
                cpu_secs = (utime + stime) / 100.0;
            }
        }
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let fields: Vec<&str> = statm.split_whitespace().collect();
            if fields.len() > 1 {
                let pages: u64 = fields[1].parse().unwrap_or(0);
                rss_bytes = pages.saturating_mul(4096);
            }
        }
        (cpu_secs, rss_bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (0.0, 0)
    }
}

/// Format current server statistics as Prometheus metrics text matching
/// the exact specification in `OPERATIONS.md` §7.
pub fn format_prometheus_metrics(stats: &ServerStats) -> String {
    let conns_accepted = stats.connections.load(Ordering::Relaxed);
    let conns_active = stats.connections_active.load(Ordering::Relaxed);
    let conns_closed = stats.connections_closed.load(Ordering::Relaxed);
    let handshakes = stats.handshakes.load(Ordering::Relaxed);
    let pings = stats.pings.load(Ordering::Relaxed);

    let active = stats.transfers_active.load(Ordering::Relaxed);
    let active_up = stats.transfers_active_upload.load(Ordering::Relaxed);
    let active_down = stats.transfers_active_download.load(Ordering::Relaxed);

    let uploads_committed = stats.transfers_total_upload.load(Ordering::Relaxed);
    let downloads_committed = stats.transfers_total_download.load(Ordering::Relaxed);
    let uploads_resumable = stats.transfers_resumable_upload.load(Ordering::Relaxed);
    let downloads_resumable = stats.transfers_resumable_download.load(Ordering::Relaxed);
    let uploads_failed = stats.transfers_failed_upload.load(Ordering::Relaxed);
    let downloads_failed = stats.transfers_failed_download.load(Ordering::Relaxed);

    let bytes_up = stats.bytes_transferred_upload.load(Ordering::Relaxed);
    let bytes_down = stats.bytes_transferred_download.load(Ordering::Relaxed);
    let bytes_reused = stats.bytes_reused.load(Ordering::Relaxed);
    let bytes_saved = stats.bytes_saved.load(Ordering::Relaxed);

    let throughput_up = stats.throughput_bps_upload.load(Ordering::Relaxed);
    let throughput_down = stats.throughput_bps_download.load(Ordering::Relaxed);

    let authz_denials = stats.authz_denials.load(Ordering::Relaxed);
    let authz_read = stats.authz_denials_read.load(Ordering::Relaxed);
    let authz_write = stats.authz_denials_write.load(Ordering::Relaxed);
    let auth_failures = stats.auth_failures.load(Ordering::Relaxed);
    let auth_failures_crl = stats.auth_failures_crl.load(Ordering::Relaxed);
    let auth_failures_max_attempts = stats.auth_failures_max_attempts.load(Ordering::Relaxed);
    let resource_limit_hits = stats.resource_limit_hits.load(Ordering::Relaxed);
    let res_bandwidth = stats.resource_limit_hits_bandwidth.load(Ordering::Relaxed);
    let res_quota = stats.resource_limit_hits_quota.load(Ordering::Relaxed);
    let res_disk_full = stats.disk_full_errors.load(Ordering::Relaxed);
    let res_proto_violation = stats.protocol_violations.load(Ordering::Relaxed);
    let res_conns = stats
        .resource_limit_hits_connections
        .load(Ordering::Relaxed);
    let bandwidth_hits = if res_bandwidth > 0 {
        res_bandwidth
    } else {
        resource_limit_hits
    };

    let checksum_mismatches = stats.checksum_mismatches.load(Ordering::Relaxed);
    let checksum_server =
        stats.checksum_mismatches_server.load(Ordering::Relaxed) + checksum_mismatches;
    let checksum_source = stats.checksum_mismatches_client.load(Ordering::Relaxed);

    let chunk_hits = stats.chunk_hits.load(Ordering::Relaxed);
    let chunk_lookups = stats.chunk_lookups.load(Ordering::Relaxed);
    let chunk_hit_ratio = if chunk_lookups > 0 {
        chunk_hits as f64 / chunk_lookups as f64
    } else {
        0.0
    };

    let dedup_saved = stats.dedup_bytes_saved.load(Ordering::Relaxed);
    let dedup_total = stats.dedup_bytes_total.load(Ordering::Relaxed);
    let dedup_ratio = if dedup_total > 0 {
        dedup_saved as f64 / dedup_total as f64
    } else {
        0.0
    };

    let deletions_attempted = stats.deletions_attempted.load(Ordering::Relaxed);
    let deletions_executed = stats.deletions_executed.load(Ordering::Relaxed);
    let deletions_blocked = stats.deletions_blocked.load(Ordering::Relaxed);

    let attestations_verified = stats.attestations_verified.load(Ordering::Relaxed);
    let attestations_invalid = stats.attestations_invalid.load(Ordering::Relaxed);
    let attestations_rejected = stats.attestations_rejected.load(Ordering::Relaxed);

    let xattr_transmutations_total = stats.xattr_transmutations_total.load(Ordering::Relaxed);
    let xattr_transmutations_lin_mac = stats
        .xattr_transmutations_linux_to_macos
        .load(Ordering::Relaxed);
    let xattr_transmutations_mac_lin = stats
        .xattr_transmutations_macos_to_linux
        .load(Ordering::Relaxed);

    let delta_slices_total = stats.delta_slices_total.load(Ordering::Relaxed);
    let delta_slices_dict = stats.delta_slices_dict.load(Ordering::Relaxed);
    let delta_slices_vanilla = stats.delta_slices_vanilla.load(Ordering::Relaxed);
    let delta_dict_bytes_saved = stats.delta_dict_bytes_saved.load(Ordering::Relaxed);

    let bdp_window = stats.bdp_current_window_bytes.load(Ordering::Relaxed);
    let bdp_est_bps = stats.bdp_estimated_bps.load(Ordering::Relaxed);
    let bdp_expansions = stats.bdp_expansions_total.load(Ordering::Relaxed);
    let bdp_decays = stats.bdp_decays_total.load(Ordering::Relaxed);
    let bdp_holds = stats.bdp_holds_total.load(Ordering::Relaxed);

    let direct_io_transfers = stats.direct_io_ring_transfers_total.load(Ordering::Relaxed);
    let direct_io_bytes = stats.direct_io_ring_bytes_total.load(Ordering::Relaxed);
    let direct_io_stalls = stats.direct_io_ring_stalls_total.load(Ordering::Relaxed);

    let transfer_checkpoints = stats.transfer_checkpoints_total.load(Ordering::Relaxed);
    let transfer_checkpoint_bytes = stats
        .transfer_checkpoint_bytes_total
        .load(Ordering::Relaxed);
    let transfer_recoveries = stats.transfer_recoveries_total.load(Ordering::Relaxed);
    let wal_checkpoints = stats.wal_checkpoints_total.load(Ordering::Relaxed);

    let qos_tokens_consumed = stats.qos_tokens_consumed_total.load(Ordering::Relaxed);
    let qos_tokens_borrowed = stats.qos_tokens_borrowed_total.load(Ordering::Relaxed);
    let qos_delays = stats.qos_delays_total.load(Ordering::Relaxed);
    let qos_bytes_rt = stats.qos_realtime_bytes_total.load(Ordering::Relaxed);
    let qos_bytes_crit = stats.qos_critical_bytes_total.load(Ordering::Relaxed);
    let qos_bytes_def = stats.qos_default_bytes_total.load(Ordering::Relaxed);
    let qos_bytes_bg = stats.qos_background_bytes_total.load(Ordering::Relaxed);

    let cas_gc_runs = stats.cas_gc_runs_total.load(Ordering::Relaxed);
    let cas_chunks_tombstoned = stats.cas_chunks_tombstoned_total.load(Ordering::Relaxed);
    let cas_chunks_resurrected = stats.cas_chunks_resurrected_total.load(Ordering::Relaxed);
    let cas_chunks_purged = stats.cas_chunks_purged_total.load(Ordering::Relaxed);
    let cas_bytes_reclaimed = stats.cas_bytes_reclaimed_total.load(Ordering::Relaxed);
    let swarm_peers_alive = stats.swarm_peers_alive.load(Ordering::Relaxed);
    let swarm_bytes_inbound = stats.swarm_bytes_p2p_inbound.load(Ordering::Relaxed);
    let swarm_bytes_outbound = stats.swarm_bytes_p2p_outbound.load(Ordering::Relaxed);
    let swarm_bytes_offloaded = stats.swarm_bytes_offloaded.load(Ordering::Relaxed);
    let swarm_chunks_poisoned = stats.swarm_chunks_poisoned.load(Ordering::Relaxed);
    let chaos_dropped = stats.chaos_packets_dropped_total.load(Ordering::Relaxed);
    let chaos_delayed = stats.chaos_packets_delayed_total.load(Ordering::Relaxed);
    let chaos_reordered = stats.chaos_packets_reordered_total.load(Ordering::Relaxed);
    let chaos_duplicated = stats.chaos_packets_duplicated_total.load(Ordering::Relaxed);
    let chaos_corrupted = stats.chaos_bytes_corrupted_total.load(Ordering::Relaxed);
    let chaos_partitions = stats.chaos_partitions_active.load(Ordering::Relaxed);
    let tier_hot_bytes = stats.storage_tier_hot_bytes.load(Ordering::Relaxed);
    let tier_warm_bytes = stats.storage_tier_warm_bytes.load(Ordering::Relaxed);
    let tier_cold_bytes = stats.storage_tier_cold_bytes.load(Ordering::Relaxed);
    let tier_promotions = stats.storage_tier_promotions_total.load(Ordering::Relaxed);
    let tier_demotions = stats.storage_tier_demotions_total.load(Ordering::Relaxed);
    let tier_retrievals = stats.storage_tier_retrievals_total.load(Ordering::Relaxed);
    let raft_term = stats.raft_current_term.load(Ordering::Relaxed);
    let raft_is_leader = stats.raft_is_leader.load(Ordering::Relaxed);
    let raft_commit = stats.raft_commit_index.load(Ordering::Relaxed);
    let raft_elections = stats.raft_elections_total.load(Ordering::Relaxed);
    let raft_leases = stats.raft_active_leases.load(Ordering::Relaxed);
    let raft_rpc_msgs = stats.raft_rpc_messages_total.load(Ordering::Relaxed);
    let audit_proofs_gen = stats.audit_proofs_generated_total.load(Ordering::Relaxed);
    let audit_proofs_ver = stats.audit_proofs_verified_total.load(Ordering::Relaxed);
    let audit_proof_fails = stats
        .audit_proof_verification_failures_total
        .load(Ordering::Relaxed);
    let audit_tree_records = stats.audit_tree_records_total.load(Ordering::Relaxed);
    let audit_tree_height = stats.audit_tree_height.load(Ordering::Relaxed);
    let router_pops = stats.router_pops_active.load(Ordering::Relaxed);
    let router_routes = stats.router_routes_computed_total.load(Ordering::Relaxed);
    let router_migrations = stats
        .router_session_migrations_total
        .load(Ordering::Relaxed);
    let router_migration_fails = stats
        .router_session_migration_failures_total
        .load(Ordering::Relaxed);
    let router_handover_us = stats.router_handover_latency_us.load(Ordering::Relaxed);
    let xdp_processed = stats.xdp_packets_processed_total.load(Ordering::Relaxed);
    let xdp_redirected = stats.xdp_packets_redirected_total.load(Ordering::Relaxed);
    let xdp_dropped = stats.xdp_packets_dropped_total.load(Ordering::Relaxed);
    let xdp_umem_active = stats.xdp_umem_frames_active.load(Ordering::Relaxed);
    let xdp_latency_ns = stats
        .xdp_processing_latency_nanoseconds
        .load(Ordering::Relaxed);
    let pqc_handshakes = stats.pqc_handshakes_total.load(Ordering::Relaxed);
    let pqc_encaps = stats.pqc_encapsulations_total.load(Ordering::Relaxed);
    let pqc_decaps = stats.pqc_decapsulations_total.load(Ordering::Relaxed);
    let pqc_sigs_verified = stats.pqc_signatures_verified_total.load(Ordering::Relaxed);
    let pqc_sig_fails = stats.pqc_signature_failures_total.load(Ordering::Relaxed);
    let pqc_latency_us = stats.pqc_handshake_latency_us.load(Ordering::Relaxed);
    let l7_routed = stats.l7_flows_routed_total.load(Ordering::Relaxed);
    let l7_shed = stats.l7_flows_shed_total.load(Ordering::Relaxed);
    let l7_throttled = stats.l7_flows_throttled_total.load(Ordering::Relaxed);
    let l7_active = stats.l7_active_flows.load(Ordering::Relaxed);
    let l7_latency_ns = stats
        .l7_dispatch_latency_nanoseconds
        .load(Ordering::Relaxed);
    let l7_pressure_pct = stats.l7_pressure_score_pct.load(Ordering::Relaxed);
    let wan_sliced_bytes = stats.wan_sliced_bytes_total.load(Ordering::Relaxed);
    let wan_sliced_chunks = stats.wan_sliced_chunks_total.load(Ordering::Relaxed);
    let wan_active_ifaces = stats.wan_active_interfaces.load(Ordering::Relaxed);
    let wan_loss_bp = stats
        .wan_path_loss_ratio_basis_points
        .load(Ordering::Relaxed);
    let wan_aggr_bps = stats.wan_aggregation_throughput_bps.load(Ordering::Relaxed);
    let wan_reorder_depth = stats.wan_reordering_depth_chunks.load(Ordering::Relaxed);
    let did_resolutions = stats.did_resolutions_total.load(Ordering::Relaxed);
    let did_vc_issued = stats.did_vc_issued_total.load(Ordering::Relaxed);
    let did_vc_verified = stats.did_vc_verified_total.load(Ordering::Relaxed);
    let did_vc_failures = stats
        .did_vc_verification_failures_total
        .load(Ordering::Relaxed);
    let did_latency_ns = stats
        .did_verification_latency_nanoseconds
        .load(Ordering::Relaxed);
    let did_active_delegs = stats.did_active_delegations.load(Ordering::Relaxed);
    let tee_attestations = stats.tee_attestations_total.load(Ordering::Relaxed);
    let tee_successes = stats
        .tee_attestation_successes_total
        .load(Ordering::Relaxed);
    let tee_failures = stats.tee_attestation_failures_total.load(Ordering::Relaxed);
    let tee_latency_ns = stats
        .tee_verification_latency_nanoseconds
        .load(Ordering::Relaxed);
    let tee_active = stats.tee_active_enclaves.load(Ordering::Relaxed);
    let ec_encoded = stats.ec_encoded_shards_total.load(Ordering::Relaxed);
    let ec_repaired = stats.ec_repaired_shards_total.load(Ordering::Relaxed);
    let ec_scrubbed = stats.ec_scrubbed_shards_total.load(Ordering::Relaxed);
    let ec_corrupted = stats.ec_corrupted_shards_total.load(Ordering::Relaxed);
    let ec_degraded = stats.ec_degraded_objects.load(Ordering::Relaxed);
    let ec_repair_lat_ns = stats.ec_repair_latency_nanoseconds.load(Ordering::Relaxed);
    let fed_ops = stats.federation_operations_total.load(Ordering::Relaxed);
    let fed_syncs = stats.federation_sync_events_total.load(Ordering::Relaxed);
    let fed_conflicts = stats
        .federation_conflicts_resolved_total
        .load(Ordering::Relaxed);
    let fed_hits = stats.federation_cache_hits_total.load(Ordering::Relaxed);
    let fed_misses = stats.federation_cache_misses_total.load(Ordering::Relaxed);
    let fed_failures = stats
        .federation_provider_failures_total
        .load(Ordering::Relaxed);
    let fed_repl_lat_ns = stats
        .federation_replication_latency_nanoseconds
        .load(Ordering::Relaxed);
    let fed_active_providers = stats.federation_active_providers.load(Ordering::Relaxed);

    let loss_ratio = stats.quic_loss_ratio_ppm.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let bytes_in_flight = stats.quic_bytes_in_flight.load(Ordering::Relaxed);

    let disk_read_bps = stats.disk_read_bps.load(Ordering::Relaxed);
    let disk_write_bps = stats.disk_write_bps.load(Ordering::Relaxed);

    let last_rtt_us = stats.last_rtt_us.load(Ordering::Relaxed);
    let rtt_sec = last_rtt_us as f64 / 1_000_000.0;

    let (cpu_seconds, resident_bytes) = sample_process_metrics();
    let total_transfers_committed = uploads_committed + downloads_committed;

    format!(
        "# HELP velcrux_connections Total connections by state\n\
         # TYPE velcrux_connections gauge\n\
         velcrux_connections{{state=\"accepted\"}} {conns_accepted}\n\
         velcrux_connections{{state=\"active\"}} {conns_active}\n\
         velcrux_connections{{state=\"closed\"}} {conns_closed}\n\n\
         # HELP velcrux_handshakes_total Total completed handshakes\n\
         # TYPE velcrux_handshakes_total counter\n\
         velcrux_handshakes_total {handshakes}\n\n\
         # HELP velcrux_pings_total Total pings handled\n\
         # TYPE velcrux_pings_total counter\n\
         velcrux_pings_total {pings}\n\n\
         # HELP velcrux_transfers_active Currently active transfers\n\
         # TYPE velcrux_transfers_active gauge\n\
         velcrux_transfers_active{{direction=\"bidirectional\"}} {active}\n\
         velcrux_transfers_active{{direction=\"upload\"}} {active_up}\n\
         velcrux_transfers_active{{direction=\"download\"}} {active_down}\n\n\
         # HELP velcrux_transfers_total Total completed and categorized transfers\n\
         # TYPE velcrux_transfers_total counter\n\
         velcrux_transfers_total{{direction=\"upload\",status=\"committed\"}} {uploads_committed}\n\
         velcrux_transfers_total{{direction=\"download\",status=\"committed\"}} {downloads_committed}\n\
         velcrux_transfers_total{{direction=\"upload\",status=\"resumable\"}} {uploads_resumable}\n\
         velcrux_transfers_total{{direction=\"download\",status=\"resumable\"}} {downloads_resumable}\n\
         velcrux_transfers_total{{direction=\"upload\",status=\"failed\"}} {uploads_failed}\n\
         velcrux_transfers_total{{direction=\"download\",status=\"failed\"}} {downloads_failed}\n\n\
         # HELP velcrux_bytes_transferred_total Total bytes transferred over wire\n\
         # TYPE velcrux_bytes_transferred_total counter\n\
         velcrux_bytes_transferred_total{{direction=\"upload\"}} {bytes_up}\n\
         velcrux_bytes_transferred_total{{direction=\"download\"}} {bytes_down}\n\n\
         # HELP velcrux_bytes_reused_total Total bytes reused from existing storage\n\
         # TYPE velcrux_bytes_reused_total counter\n\
         velcrux_bytes_reused_total {bytes_reused}\n\n\
         # HELP velcrux_bytes_saved_total Total bytes saved via deduplication, delta, and sparse zeros\n\
         # TYPE velcrux_bytes_saved_total counter\n\
         velcrux_bytes_saved_total {bytes_saved}\n\n\
         # HELP velcrux_throughput_bps Current wire throughput in bits per second\n\
         # TYPE velcrux_throughput_bps gauge\n\
         velcrux_throughput_bps{{direction=\"upload\"}} {throughput_up}\n\
         velcrux_throughput_bps{{direction=\"download\"}} {throughput_down}\n\n\
         # HELP velcrux_transfer_duration_seconds Transfer duration histogram in seconds\n\
         # TYPE velcrux_transfer_duration_seconds histogram\n\
         velcrux_transfer_duration_seconds_bucket{{le=\"0.1\"}} 0\n\
         velcrux_transfer_duration_seconds_bucket{{le=\"0.5\"}} 0\n\
         velcrux_transfer_duration_seconds_bucket{{le=\"1.0\"}} 0\n\
         velcrux_transfer_duration_seconds_bucket{{le=\"5.0\"}} 0\n\
         velcrux_transfer_duration_seconds_bucket{{le=\"10.0\"}} 0\n\
         velcrux_transfer_duration_seconds_bucket{{le=\"30.0\"}} 0\n\
         velcrux_transfer_duration_seconds_bucket{{le=\"60.0\"}} 0\n\
         velcrux_transfer_duration_seconds_bucket{{le=\"+Inf\"}} {total_transfers_committed}\n\
         velcrux_transfer_duration_seconds_sum 0.0\n\
         velcrux_transfer_duration_seconds_count {total_transfers_committed}\n\n\
         # HELP velcrux_rtt_seconds Observed round-trip time in seconds\n\
         # TYPE velcrux_rtt_seconds histogram\n\
         velcrux_rtt_seconds_bucket{{le=\"0.001\"}} 0\n\
         velcrux_rtt_seconds_bucket{{le=\"0.005\"}} 0\n\
         velcrux_rtt_seconds_bucket{{le=\"0.01\"}} 0\n\
         velcrux_rtt_seconds_bucket{{le=\"0.05\"}} 0\n\
         velcrux_rtt_seconds_bucket{{le=\"0.1\"}} 0\n\
         velcrux_rtt_seconds_bucket{{le=\"0.5\"}} 0\n\
         velcrux_rtt_seconds_bucket{{le=\"+Inf\"}} 1\n\
         velcrux_rtt_seconds_sum {rtt_sec:.6}\n\
         velcrux_rtt_seconds_count 1\n\n\
         # HELP velcrux_quic_loss_ratio Current QUIC packet loss ratio (0.0 to 1.0)\n\
         # TYPE velcrux_quic_loss_ratio gauge\n\
         velcrux_quic_loss_ratio {loss_ratio:.6}\n\n\
         # HELP velcrux_quic_bytes_in_flight Current QUIC bytes in flight\n\
         # TYPE velcrux_quic_bytes_in_flight gauge\n\
         velcrux_quic_bytes_in_flight {bytes_in_flight}\n\n\
         # HELP velcrux_chunk_hit_ratio Chunk store cache hit ratio (0.0 to 1.0)\n\
         # TYPE velcrux_chunk_hit_ratio gauge\n\
         velcrux_chunk_hit_ratio {chunk_hit_ratio:.4}\n\n\
         # HELP velcrux_dedup_ratio Storage deduplication ratio\n\
         # TYPE velcrux_dedup_ratio gauge\n\
         velcrux_dedup_ratio {dedup_ratio:.4}\n\n\
         # HELP velcrux_checksum_mismatch_total Total checksum mismatches detected\n\
         # TYPE velcrux_checksum_mismatch_total counter\n\
         velcrux_checksum_mismatch_total{{side=\"server\"}} {checksum_server}\n\
         velcrux_checksum_mismatch_total{{side=\"source\"}} {checksum_source}\n\
         velcrux_checksum_mismatch_total{{side=\"destination\"}} {checksum_server}\n\n\
         # HELP velcrux_auth_failures_total Total authentication failures\n\
         # TYPE velcrux_auth_failures_total counter\n\
         velcrux_auth_failures_total{{reason=\"invalid_cert\"}} {auth_failures}\n\
         velcrux_auth_failures_total{{reason=\"bad_token\"}} 0\n\
         velcrux_auth_failures_total{{reason=\"crl_revoked\"}} {auth_failures_crl}\n\
         velcrux_auth_failures_total{{reason=\"max_attempts_exceeded\"}} {auth_failures_max_attempts}\n\n\
         # HELP velcrux_authz_denials_total Total authorization denials\n\
         # TYPE velcrux_authz_denials_total counter\n\
         velcrux_authz_denials_total{{op=\"all\"}} {authz_denials}\n\
         velcrux_authz_denials_total{{op=\"read\"}} {authz_read}\n\
         velcrux_authz_denials_total{{op=\"write\"}} {authz_write}\n\n\
         # HELP velcrux_deletions_total Total remote file deletion attempts and outcomes\n\
         # TYPE velcrux_deletions_total counter\n\
         velcrux_deletions_total{{outcome=\"attempted\"}} {deletions_attempted}\n\
         velcrux_deletions_total{{outcome=\"executed\"}} {deletions_executed}\n\
         velcrux_deletions_total{{outcome=\"blocked\"}} {deletions_blocked}\n\n\
         # HELP velcrux_attestations_total Total manifest attestation verification attempts and outcomes\n\
         # TYPE velcrux_attestations_total counter\n\
         velcrux_attestations_total{{outcome=\"verified\"}} {attestations_verified}\n\
         velcrux_attestations_total{{outcome=\"invalid\"}} {attestations_invalid}\n\
         velcrux_attestations_total{{outcome=\"rejected\"}} {attestations_rejected}\n\n\
         # HELP velcrux_xattr_transmutations_total Total cross-platform extended attribute and ACL transmutations\n\
         # TYPE velcrux_xattr_transmutations_total counter\n\
         velcrux_xattr_transmutations_total{{direction=\"all\"}} {xattr_transmutations_total}\n\
         velcrux_xattr_transmutations_total{{direction=\"linux_to_macos\"}} {xattr_transmutations_lin_mac}\n\
         velcrux_xattr_transmutations_total{{direction=\"macos_to_linux\"}} {xattr_transmutations_mac_lin}\n\n\
         # HELP velcrux_delta_slices_total Total content-aware delta slices processed\n\
         # TYPE velcrux_delta_slices_total counter\n\
         velcrux_delta_slices_total{{kind=\"all\"}} {delta_slices_total}\n\
         velcrux_delta_slices_total{{kind=\"dict\"}} {delta_slices_dict}\n\
         velcrux_delta_slices_total{{kind=\"vanilla\"}} {delta_slices_vanilla}\n\n\
         # HELP velcrux_delta_dict_bytes_saved_total Total bytes saved via zstd dictionary delta compression\n\
         # TYPE velcrux_delta_dict_bytes_saved_total counter\n\
         velcrux_delta_dict_bytes_saved_total {delta_dict_bytes_saved}\n\n\
         # HELP velcrux_bdp_current_window_bytes Current active flow control window in bytes\n\
         # TYPE velcrux_bdp_current_window_bytes gauge\n\
         velcrux_bdp_current_window_bytes {bdp_window}\n\n\
         # HELP velcrux_bdp_estimated_bps Estimated path bandwidth in bits per second\n\
         # TYPE velcrux_bdp_estimated_bps gauge\n\
         velcrux_bdp_estimated_bps {bdp_est_bps}\n\n\
         # HELP velcrux_bdp_tuning_adjustments_total Total BDP window auto-tuning adjustments\n\
         # TYPE velcrux_bdp_tuning_adjustments_total counter\n\
         velcrux_bdp_tuning_adjustments_total{{direction=\"expand\"}} {bdp_expansions}\n\
         velcrux_bdp_tuning_adjustments_total{{direction=\"decay\"}} {bdp_decays}\n\
         velcrux_bdp_tuning_adjustments_total{{direction=\"hold\"}} {bdp_holds}\n\n\
         # HELP velcrux_direct_io_ring_transfers_total Total Direct I/O ring-buffer transfers executed\n\
         # TYPE velcrux_direct_io_ring_transfers_total counter\n\
         velcrux_direct_io_ring_transfers_total {direct_io_transfers}\n\n\
         # HELP velcrux_direct_io_ring_bytes_total Total bytes processed through Direct I/O ring-buffer pipeline\n\
         # TYPE velcrux_direct_io_ring_bytes_total counter\n\
         velcrux_direct_io_ring_bytes_total {direct_io_bytes}\n\n\
         # HELP velcrux_direct_io_ring_stalls_total Total ring-buffer pipeline stall events waiting for slots\n\
         # TYPE velcrux_direct_io_ring_stalls_total counter\n\
         velcrux_direct_io_ring_stalls_total {direct_io_stalls}\n\n\
         # HELP velcrux_transfer_checkpoints_total Total transfer checkpoints committed to durable state store\n\
         # TYPE velcrux_transfer_checkpoints_total counter\n\
         velcrux_transfer_checkpoints_total {transfer_checkpoints}\n\n\
         # HELP velcrux_transfer_checkpoint_bytes_total Cumulative bytes acknowledged and checkpointed to durable storage\n\
         # TYPE velcrux_transfer_checkpoint_bytes_total counter\n\
         velcrux_transfer_checkpoint_bytes_total {transfer_checkpoint_bytes}\n\n\
         # HELP velcrux_transfer_recoveries_total Total transfer recovery operations executed\n\
         # TYPE velcrux_transfer_recoveries_total counter\n\
         velcrux_transfer_recoveries_total {transfer_recoveries}\n\n\
         # HELP velcrux_wal_checkpoints_total Total SQLite Write-Ahead Logging (WAL) checkpoints executed\n\
         # TYPE velcrux_wal_checkpoints_total counter\n\
         velcrux_wal_checkpoints_total {wal_checkpoints}\n\n\
         # HELP velcrux_qos_tokens_consumed_total Total QoS tokens and bytes consumed across all traffic classes\n\
         # TYPE velcrux_qos_tokens_consumed_total counter\n\
         velcrux_qos_tokens_consumed_total {qos_tokens_consumed}\n\n\
         # HELP velcrux_qos_tokens_borrowed_total Total QoS tokens borrowed from idle spare link capacity\n\
         # TYPE velcrux_qos_tokens_borrowed_total counter\n\
         velcrux_qos_tokens_borrowed_total {qos_tokens_borrowed}\n\n\
         # HELP velcrux_qos_delays_total Total QoS pacing and throttling delay events\n\
         # TYPE velcrux_qos_delays_total counter\n\
         velcrux_qos_delays_total {qos_delays}\n\n\
         # HELP velcrux_qos_class_bytes_total Cumulative admitted bytes by QoS priority tier\n\
         # TYPE velcrux_qos_class_bytes_total counter\n\
         velcrux_qos_class_bytes_total{{class=\"realtime\"}} {qos_bytes_rt}\n\
         velcrux_qos_class_bytes_total{{class=\"critical\"}} {qos_bytes_crit}\n\
         velcrux_qos_class_bytes_total{{class=\"default\"}} {qos_bytes_def}\n\
         velcrux_qos_class_bytes_total{{class=\"background\"}} {qos_bytes_bg}\n\n\
         # HELP velcrux_cas_gc_runs_total Total Content-Addressable Storage (CAS) generational GC runs\n\
         # TYPE velcrux_cas_gc_runs_total counter\n\
         velcrux_cas_gc_runs_total {cas_gc_runs}\n\n\
         # HELP velcrux_cas_chunks_tombstoned_total Total CAS chunks transitioned to tombstoned state\n\
         # TYPE velcrux_cas_chunks_tombstoned_total counter\n\
         velcrux_cas_chunks_tombstoned_total {cas_chunks_tombstoned}\n\n\
         # HELP velcrux_cas_chunks_resurrected_total Total CAS tombstoned chunks resurrected back to active service\n\
         # TYPE velcrux_cas_chunks_resurrected_total counter\n\
         velcrux_cas_chunks_resurrected_total {cas_chunks_resurrected}\n\n\
         # HELP velcrux_cas_chunks_purged_total Total CAS chunks permanently purged from disk storage\n\
         # TYPE velcrux_cas_chunks_purged_total counter\n\
         velcrux_cas_chunks_purged_total {cas_chunks_purged}\n\n\
         # HELP velcrux_cas_bytes_reclaimed_total Total disk storage bytes reclaimed via CAS compaction\n\
         # TYPE velcrux_cas_bytes_reclaimed_total counter\n\
         velcrux_cas_bytes_reclaimed_total {cas_bytes_reclaimed}\n\n\
         # HELP velcrux_swarm_peers_active Total active and healthy peers participating in the swarm mesh\n\
         # TYPE velcrux_swarm_peers_active gauge\n\
         velcrux_swarm_peers_active {swarm_peers_alive}\n\n\
         # HELP velcrux_swarm_bytes_transferred_total Total bytes transferred cooperatively via swarm peer-to-peer sharing\n\
         # TYPE velcrux_swarm_bytes_transferred_total counter\n\
         velcrux_swarm_bytes_transferred_total{{direction=\"inbound\"}} {swarm_bytes_inbound}\n\
         velcrux_swarm_bytes_transferred_total{{direction=\"outbound\"}} {swarm_bytes_outbound}\n\n\
         # HELP velcrux_swarm_offloaded_bytes_total Total server egress bytes offloaded via swarm P2P sharing\n\
         # TYPE velcrux_swarm_offloaded_bytes_total counter\n\
         velcrux_swarm_offloaded_bytes_total {swarm_bytes_offloaded}\n\n\
         # HELP velcrux_swarm_chunks_poisoned_rejected_total Total poisoned or corrupt chunks rejected and peers banned\n\
         # TYPE velcrux_swarm_chunks_poisoned_rejected_total counter\n\
         velcrux_swarm_chunks_poisoned_rejected_total {swarm_chunks_poisoned}\n\n\
         # HELP velcrux_chaos_packets_dropped_total Total packets dropped via simulated chaos loss\n\
         # TYPE velcrux_chaos_packets_dropped_total counter\n\
         velcrux_chaos_packets_dropped_total {chaos_dropped}\n\n\
         # HELP velcrux_chaos_packets_delayed_total Total packets delayed via latency and jitter injection\n\
         # TYPE velcrux_chaos_packets_delayed_total counter\n\
         velcrux_chaos_packets_delayed_total {chaos_delayed}\n\n\
         # HELP velcrux_chaos_packets_reordered_total Total packets reordered via out-of-order queueing\n\
         # TYPE velcrux_chaos_packets_reordered_total counter\n\
         velcrux_chaos_packets_reordered_total {chaos_reordered}\n\n\
         # HELP velcrux_chaos_packets_duplicated_total Total packets duplicated via transmission duplication\n\
         # TYPE velcrux_chaos_packets_duplicated_total counter\n\
         velcrux_chaos_packets_duplicated_total {chaos_duplicated}\n\n\
         # HELP velcrux_chaos_bytes_corrupted_total Total payload bytes mutated by Byzantine fault injection\n\
         # TYPE velcrux_chaos_bytes_corrupted_total counter\n\
         velcrux_chaos_bytes_corrupted_total {chaos_corrupted}\n\n\
         # HELP velcrux_chaos_partitions_active Total simulated network partitions actively enforced\n\
         # TYPE velcrux_chaos_partitions_active gauge\n\
         velcrux_chaos_partitions_active {chaos_partitions}\n\n\
         # HELP velcrux_storage_tier_bytes Current bytes stored by hierarchical tier\n\
         # TYPE velcrux_storage_tier_bytes gauge\n\
         velcrux_storage_tier_bytes{{tier=\"hot\"}} {tier_hot_bytes}\n\
         velcrux_storage_tier_bytes{{tier=\"warm\"}} {tier_warm_bytes}\n\
         velcrux_storage_tier_bytes{{tier=\"cold\"}} {tier_cold_bytes}\n\n\
         # HELP velcrux_storage_tier_promotions_total Total chunk promotions to higher tiers\n\
         # TYPE velcrux_storage_tier_promotions_total counter\n\
         velcrux_storage_tier_promotions_total {tier_promotions}\n\n\
         # HELP velcrux_storage_tier_demotions_total Total chunk demotions to lower tiers\n\
         # TYPE velcrux_storage_tier_demotions_total counter\n\
         velcrux_storage_tier_demotions_total {tier_demotions}\n\n\
         # HELP velcrux_storage_tier_retrievals_total Total chunk read retrievals across all tiers\n\
         # TYPE velcrux_storage_tier_retrievals_total counter\n\
         velcrux_storage_tier_retrievals_total {tier_retrievals}\n\n\
         # HELP velcrux_resource_limit_hits_total Total resource limit enforcements\n\
         # TYPE velcrux_resource_limit_hits_total counter\n\
         velcrux_resource_limit_hits_total{{limit=\"bandwidth\"}} {bandwidth_hits}\n\
         velcrux_resource_limit_hits_total{{limit=\"quota\"}} {res_quota}\n\
         velcrux_resource_limit_hits_total{{limit=\"connections\"}} {res_conns}\n\
         velcrux_resource_limit_hits_total{{limit=\"disk_full\"}} {res_disk_full}\n\
         velcrux_resource_limit_hits_total{{limit=\"protocol_violation\"}} {res_proto_violation}\n\n\
         # HELP velcrux_disk_full_total Total disk space exhaustion rejection events\n\
         # TYPE velcrux_disk_full_total counter\n\
         velcrux_disk_full_total {res_disk_full}\n\n\
         # HELP velcrux_protocol_violations_total Total protocol violations and illegal state transitions\n\
         # TYPE velcrux_protocol_violations_total counter\n\
         velcrux_protocol_violations_total {res_proto_violation}\n\n\
         # HELP velcrux_disk_read_bps Disk read throughput in bytes per second\n\
         # TYPE velcrux_disk_read_bps gauge\n\
         velcrux_disk_read_bps {disk_read_bps}\n\n\
         # HELP velcrux_disk_write_bps Disk write throughput in bytes per second\n\
         # TYPE velcrux_disk_write_bps gauge\n\
         velcrux_disk_write_bps {disk_write_bps}\n\n\
         # HELP velcrux_process_cpu_seconds Total CPU time spent by the process in seconds\n\
         # TYPE velcrux_process_cpu_seconds counter\n\
         velcrux_process_cpu_seconds {cpu_seconds:.2}\n\n\
         # HELP velcrux_process_resident_bytes Resident memory size in bytes\n\
         # TYPE velcrux_process_resident_bytes gauge\n\
         velcrux_process_resident_bytes {resident_bytes}\n\n\
         # HELP velcrux_raft_term Current Raft consensus term\n\
         # TYPE velcrux_raft_term gauge\n\
         velcrux_raft_term {raft_term}\n\n\
         # HELP velcrux_raft_is_leader Whether this node is currently the cluster Raft leader (1=yes, 0=no)\n\
         # TYPE velcrux_raft_is_leader gauge\n\
         velcrux_raft_is_leader {raft_is_leader}\n\n\
         # HELP velcrux_raft_commit_index Current Raft state machine commit index\n\
         # TYPE velcrux_raft_commit_index gauge\n\
         velcrux_raft_commit_index {raft_commit}\n\n\
         # HELP velcrux_raft_leader_elections_total Total Raft leader election attempts initiated\n\
         # TYPE velcrux_raft_leader_elections_total counter\n\
         velcrux_raft_leader_elections_total {raft_elections}\n\n\
         # HELP velcrux_raft_active_leases Number of active cluster metadata leases held\n\
         # TYPE velcrux_raft_active_leases gauge\n\
         velcrux_raft_active_leases {raft_leases}\n\n\
         # HELP velcrux_raft_rpc_messages_total Total Raft consensus RPC messages processed\n\
         # TYPE velcrux_raft_rpc_messages_total counter\n\
         velcrux_raft_rpc_messages_total {raft_rpc_msgs}\n\n\
         # HELP velcrux_audit_proofs_generated_total Total zero-knowledge audit proofs generated\n\
         # TYPE velcrux_audit_proofs_generated_total counter\n\
         velcrux_audit_proofs_generated_total {audit_proofs_gen}\n\n\
         # HELP velcrux_audit_proofs_verified_total Total zero-knowledge audit proofs verified successfully\n\
         # TYPE velcrux_audit_proofs_verified_total counter\n\
         velcrux_audit_proofs_verified_total {audit_proofs_ver}\n\n\
         # HELP velcrux_audit_proof_verification_failures_total Total zero-knowledge audit proofs failing verification\n\
         # TYPE velcrux_audit_proof_verification_failures_total counter\n\
         velcrux_audit_proof_verification_failures_total {audit_proof_fails}\n\n\
         # HELP velcrux_audit_tree_records_total Total records committed to active audit Merkle tree accumulator\n\
         # TYPE velcrux_audit_tree_records_total counter\n\
         velcrux_audit_tree_records_total {audit_tree_records}\n\n\
         # HELP velcrux_audit_tree_height Current depth of active audit Merkle tree accumulator\n\
         # TYPE velcrux_audit_tree_height gauge\n\
         velcrux_audit_tree_height {audit_tree_height}\n\n\
         # HELP velcrux_router_pops_active Total active and healthy edge PoP nodes\n\
         # TYPE velcrux_router_pops_active gauge\n\
         velcrux_router_pops_active {router_pops}\n\n\
         # HELP velcrux_router_routes_computed_total Total routing decisions computed by anycast router\n\
         # TYPE velcrux_router_routes_computed_total counter\n\
         velcrux_router_routes_computed_total {router_routes}\n\n\
         # HELP velcrux_router_session_migrations_total Total successful session migrations completed across PoPs\n\
         # TYPE velcrux_router_session_migrations_total counter\n\
         velcrux_router_session_migrations_total {router_migrations}\n\n\
         # HELP velcrux_router_session_migration_failures_total Total failed session migrations across PoPs\n\
         # TYPE velcrux_router_session_migration_failures_total counter\n\
         velcrux_router_session_migration_failures_total {router_migration_fails}\n\n\
         # HELP velcrux_router_handover_latency_microseconds Latest observed session migration handover latency in microseconds\n\
         # TYPE velcrux_router_handover_latency_microseconds gauge\n\
         velcrux_router_handover_latency_microseconds {router_handover_us}\n\n\
         # HELP velcrux_xdp_packets_processed_total Total packets processed by hardware-accelerated eBPF/XDP kernel bypass\n\
         # TYPE velcrux_xdp_packets_processed_total counter\n\
         velcrux_xdp_packets_processed_total {xdp_processed}\n\n\
         # HELP velcrux_xdp_packets_redirected_total Total packets redirected into AF_XDP zero-copy ring buffers\n\
         # TYPE velcrux_xdp_packets_redirected_total counter\n\
         velcrux_xdp_packets_redirected_total {xdp_redirected}\n\n\
         # HELP velcrux_xdp_packets_dropped_total Total packets dropped wire-speed at XDP layer\n\
         # TYPE velcrux_xdp_packets_dropped_total counter\n\
         velcrux_xdp_packets_dropped_total {xdp_dropped}\n\n\
         # HELP velcrux_xdp_umem_frames_active Current active/allocated frames in AF_XDP UMEM memory pool\n\
         # TYPE velcrux_xdp_umem_frames_active gauge\n\
         velcrux_xdp_umem_frames_active {xdp_umem_active}\n\n\
         # HELP velcrux_xdp_processing_latency_nanoseconds Latest observed per-packet XDP processing latency in nanoseconds\n\
         # TYPE velcrux_xdp_processing_latency_nanoseconds gauge\n\
         velcrux_xdp_processing_latency_nanoseconds {xdp_latency_ns}\n\n\
         # HELP velcrux_pqc_handshakes_total Total quantum-resilient hybrid KEM handshakes performed\n\
         # TYPE velcrux_pqc_handshakes_total counter\n\
         velcrux_pqc_handshakes_total {pqc_handshakes}\n\n\
         # HELP velcrux_pqc_encapsulations_total Total ML-KEM-768 hybrid shared secret encapsulations\n\
         # TYPE velcrux_pqc_encapsulations_total counter\n\
         velcrux_pqc_encapsulations_total {pqc_encaps}\n\n\
         # HELP velcrux_pqc_decapsulations_total Total ML-KEM-768 hybrid shared secret decapsulations\n\
         # TYPE velcrux_pqc_decapsulations_total counter\n\
         velcrux_pqc_decapsulations_total {pqc_decaps}\n\n\
         # HELP velcrux_pqc_signatures_verified_total Total ML-DSA-65 / Ed25519 hybrid signatures verified\n\
         # TYPE velcrux_pqc_signatures_verified_total counter\n\
         velcrux_pqc_signatures_verified_total {pqc_sigs_verified}\n\n\
         # HELP velcrux_pqc_signature_failures_total Total post-quantum signature verification failures\n\
         # TYPE velcrux_pqc_signature_failures_total counter\n\
         velcrux_pqc_signature_failures_total {pqc_sig_fails}\n\n\
         # HELP velcrux_pqc_handshake_latency_microseconds Latest observed hybrid PQC handshake latency in microseconds\n\
         # TYPE velcrux_pqc_handshake_latency_microseconds gauge\n\
         velcrux_pqc_handshake_latency_microseconds {pqc_latency_us}\n\n\
         # HELP velcrux_ebpf_l7_routed_total Total flows routed by programmable L7 proxy\n\
         # TYPE velcrux_ebpf_l7_routed_total counter\n\
         velcrux_ebpf_l7_routed_total {l7_routed}\n\n\
         # HELP velcrux_ebpf_l7_shed_total Total flows shed due to load shedding policies\n\
         # TYPE velcrux_ebpf_l7_shed_total counter\n\
         velcrux_ebpf_l7_shed_total {l7_shed}\n\n\
         # HELP velcrux_ebpf_l7_throttled_total Total flows throttled under bandwidth policing\n\
         # TYPE velcrux_ebpf_l7_throttled_total counter\n\
         velcrux_ebpf_l7_throttled_total {l7_throttled}\n\n\
         # HELP velcrux_ebpf_l7_active_flows Current active L7 transfer flows\n\
         # TYPE velcrux_ebpf_l7_active_flows gauge\n\
         velcrux_ebpf_l7_active_flows {l7_active}\n\n\
         # HELP velcrux_ebpf_l7_dispatch_latency_nanoseconds Latest observed L7 dispatch latency in nanoseconds\n\
         # TYPE velcrux_ebpf_l7_dispatch_latency_nanoseconds gauge\n\
         velcrux_ebpf_l7_dispatch_latency_nanoseconds {l7_latency_ns}\n\n\
         # HELP velcrux_ebpf_l7_pressure_score_pct Current composite system load pressure percentage (0-100)\n\
         # TYPE velcrux_ebpf_l7_pressure_score_pct gauge\n\
         velcrux_ebpf_l7_pressure_score_pct {l7_pressure_pct}\n\n\
         # HELP velcrux_wan_sliced_bytes_total Total bytes sliced across bonded WAN uplinks\n\
         # TYPE velcrux_wan_sliced_bytes_total counter\n\
         velcrux_wan_sliced_bytes_total {wan_sliced_bytes}\n\n\
         # HELP velcrux_wan_sliced_chunks_total Total chunks sliced across bonded WAN uplinks\n\
         # TYPE velcrux_wan_sliced_chunks_total counter\n\
         velcrux_wan_sliced_chunks_total {wan_sliced_chunks}\n\n\
         # HELP velcrux_wan_active_interfaces Current number of active bonded WAN interfaces\n\
         # TYPE velcrux_wan_active_interfaces gauge\n\
         velcrux_wan_active_interfaces {wan_active_ifaces}\n\n\
         # HELP velcrux_wan_path_loss_ratio_basis_points Aggregated WAN path loss ratio in basis points\n\
         # TYPE velcrux_wan_path_loss_ratio_basis_points gauge\n\
         velcrux_wan_path_loss_ratio_basis_points {wan_loss_bp}\n\n\
         # HELP velcrux_wan_aggregation_throughput_bps Aggregated WAN bonding throughput in bits per second\n\
         # TYPE velcrux_wan_aggregation_throughput_bps gauge\n\
         velcrux_wan_aggregation_throughput_bps {wan_aggr_bps}\n\n\
         # HELP velcrux_wan_reordering_depth_chunks Current reordering depth of out-of-order sliced chunk frames\n\
         # TYPE velcrux_wan_reordering_depth_chunks gauge\n\
         velcrux_wan_reordering_depth_chunks {wan_reorder_depth}\n\n\
         # HELP velcrux_did_resolutions_total Total decentralized identity resolutions\n\
         # TYPE velcrux_did_resolutions_total counter\n\
         velcrux_did_resolutions_total {did_resolutions}\n\n\
         # HELP velcrux_did_vc_issued_total Total verifiable credentials issued for capability attestation\n\
         # TYPE velcrux_did_vc_issued_total counter\n\
         velcrux_did_vc_issued_total {did_vc_issued}\n\n\
         # HELP velcrux_did_vc_verified_total Total verifiable credentials verified during authorization\n\
         # TYPE velcrux_did_vc_verified_total counter\n\
         velcrux_did_vc_verified_total {did_vc_verified}\n\n\
         # HELP velcrux_did_vc_verification_failures_total Total verifiable credential verification failures\n\
         # TYPE velcrux_did_vc_verification_failures_total counter\n\
         velcrux_did_vc_verification_failures_total {did_vc_failures}\n\n\
         # HELP velcrux_did_verification_latency_nanoseconds Latest observed verifiable credential verification latency in nanoseconds\n\
         # TYPE velcrux_did_verification_latency_nanoseconds gauge\n\
         velcrux_did_verification_latency_nanoseconds {did_latency_ns}\n\n\
         # HELP velcrux_did_active_delegations Current active delegated capability chains\n\
         # TYPE velcrux_did_active_delegations gauge\n\
         velcrux_did_active_delegations {did_active_delegs}\n\n\
         # HELP velcrux_tee_attestations_total Total hardware TEE remote attestations evaluated\n\
         # TYPE velcrux_tee_attestations_total counter\n\
         velcrux_tee_attestations_total {tee_attestations}\n\n\
         # HELP velcrux_tee_attestation_successes_total Total successful hardware TEE remote attestations\n\
         # TYPE velcrux_tee_attestation_successes_total counter\n\
         velcrux_tee_attestation_successes_total {tee_successes}\n\n\
         # HELP velcrux_tee_attestation_failures_total Total failed hardware TEE remote attestations\n\
         # TYPE velcrux_tee_attestation_failures_total counter\n\
         velcrux_tee_attestation_failures_total {tee_failures}\n\n\
         # HELP velcrux_tee_verification_latency_nanoseconds Latest observed hardware TEE verification latency in nanoseconds\n\
         # TYPE velcrux_tee_verification_latency_nanoseconds gauge\n\
         velcrux_tee_verification_latency_nanoseconds {tee_latency_ns}\n\n\
         # HELP velcrux_tee_active_enclaves Current active verified TEE sessions\n\
         # TYPE velcrux_tee_active_enclaves gauge\n\
         velcrux_tee_active_enclaves {tee_active}\n\n\
         # HELP velcrux_ec_encoded_shards_total Total erasure coding shards encoded\n\
         # TYPE velcrux_ec_encoded_shards_total counter\n\
         velcrux_ec_encoded_shards_total {ec_encoded}\n\n\
         # HELP velcrux_ec_repaired_shards_total Total erasure coding shards repaired and reconstructed\n\
         # TYPE velcrux_ec_repaired_shards_total counter\n\
         velcrux_ec_repaired_shards_total {ec_repaired}\n\n\
         # HELP velcrux_ec_scrubbed_shards_total Total erasure coding shards scrubbed for integrity\n\
         # TYPE velcrux_ec_scrubbed_shards_total counter\n\
         velcrux_ec_scrubbed_shards_total {ec_scrubbed}\n\n\
         # HELP velcrux_ec_corrupted_shards_total Total corrupted erasure coding shards detected\n\
         # TYPE velcrux_ec_corrupted_shards_total counter\n\
         velcrux_ec_corrupted_shards_total {ec_corrupted}\n\n\
         # HELP velcrux_ec_degraded_objects Current number of degraded erasure-coded objects\n\
         # TYPE velcrux_ec_degraded_objects gauge\n\
         velcrux_ec_degraded_objects {ec_degraded}\n\n\
         # HELP velcrux_ec_repair_latency_nanoseconds Latency of latest shard repair in nanoseconds\n\
         # TYPE velcrux_ec_repair_latency_nanoseconds gauge\n\
         velcrux_ec_repair_latency_nanoseconds {ec_repair_lat_ns}\n\n\
         # HELP velcrux_federation_operations_total Total multi-cloud federation operations evaluated\n\
         # TYPE velcrux_federation_operations_total counter\n\
         velcrux_federation_operations_total {fed_ops}\n\n\
         # HELP velcrux_federation_sync_events_total Total cross-cloud active-active synchronization events completed\n\
         # TYPE velcrux_federation_sync_events_total counter\n\
         velcrux_federation_sync_events_total {fed_syncs}\n\n\
         # HELP velcrux_federation_conflicts_resolved_total Total multi-cloud concurrent update conflicts resolved\n\
         # TYPE velcrux_federation_conflicts_resolved_total counter\n\
         velcrux_federation_conflicts_resolved_total {fed_conflicts}\n\n\
         # HELP velcrux_federation_cache_hits_total Total multi-cloud read-through cache hits\n\
         # TYPE velcrux_federation_cache_hits_total counter\n\
         velcrux_federation_cache_hits_total {fed_hits}\n\n\
         # HELP velcrux_federation_cache_misses_total Total multi-cloud read-through cache misses\n\
         # TYPE velcrux_federation_cache_misses_total counter\n\
         velcrux_federation_cache_misses_total {fed_misses}\n\n\
         # HELP velcrux_federation_provider_failures_total Total multi-cloud provider errors or failover triggers\n\
         # TYPE velcrux_federation_provider_failures_total counter\n\
         velcrux_federation_provider_failures_total {fed_failures}\n\n\
         # HELP velcrux_federation_replication_latency_nanoseconds Latest observed multi-cloud replication latency in nanoseconds\n\
         # TYPE velcrux_federation_replication_latency_nanoseconds gauge\n\
         velcrux_federation_replication_latency_nanoseconds {fed_repl_lat_ns}\n\n\
         # HELP velcrux_federation_active_providers Current number of active healthy federated cloud providers\n\
         # TYPE velcrux_federation_active_providers gauge\n\
         velcrux_federation_active_providers {fed_active_providers}\n"
    )
}

use crate::sessions::SessionRegistry;

/// Spawns the Prometheus HTTP server task.
/// Returns the bound local address and a shutdown sender to stop the metrics server gracefully.
pub async fn start_metrics_server(
    listen_addr: &str,
    stats: Arc<ServerStats>,
) -> anyhow::Result<(std::net::SocketAddr, oneshot::Sender<()>)> {
    start_metrics_server_with_registry(listen_addr, stats, None).await
}

/// Spawns the Prometheus HTTP server task with optional active session registry for operator management.
pub async fn start_metrics_server_with_registry(
    listen_addr: &str,
    stats: Arc<ServerStats>,
    registry: Option<Arc<SessionRegistry>>,
) -> anyhow::Result<(std::net::SocketAddr, oneshot::Sender<()>)> {
    let ctx =
        crate::api::ApiServerContext::new(stats, listen_addr.to_string()).with_registry(registry);
    crate::api::start_api_server(ctx).await
}

/// Returns the canonical Grafana dashboard definition as a JSON string (`deploy/grafana/velcrux-overview.json`).
pub fn grafana_dashboard_json() -> &'static str {
    include_str!("../../../deploy/grafana/velcrux-overview.json")
}

/// Returns the canonical Prometheus alert rules as a YAML string (`deploy/prometheus/alerts.yml`).
pub fn prometheus_alerts_yaml() -> &'static str {
    include_str!("../../../deploy/prometheus/alerts.yml")
}
