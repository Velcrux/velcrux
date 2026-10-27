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
         velcrux_raft_rpc_messages_total {raft_rpc_msgs}\n"
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
