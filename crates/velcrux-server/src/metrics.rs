//! Prometheus metrics exporter HTTP server (`OPERATIONS.md` §7).
//!
//! Exposes `/metrics` in standard Prometheus text format (`0.0.4`), `/healthz` & `/livez`
//! for Kubernetes/systemd liveness probes, and `/readyz` for readiness validation
//! on the configured `telemetry.metrics_listen` address.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{info, warn};
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
    let resource_limit_hits = stats.resource_limit_hits.load(Ordering::Relaxed);

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
         velcrux_auth_failures_total{{reason=\"bad_token\"}} 0\n\n\
         # HELP velcrux_authz_denials_total Total authorization denials\n\
         # TYPE velcrux_authz_denials_total counter\n\
         velcrux_authz_denials_total{{op=\"all\"}} {authz_denials}\n\
         velcrux_authz_denials_total{{op=\"read\"}} {authz_read}\n\
         velcrux_authz_denials_total{{op=\"write\"}} {authz_write}\n\n\
         # HELP velcrux_resource_limit_hits_total Total resource limit enforcements\n\
         # TYPE velcrux_resource_limit_hits_total counter\n\
         velcrux_resource_limit_hits_total{{limit=\"bandwidth\"}} {resource_limit_hits}\n\
         velcrux_resource_limit_hits_total{{limit=\"connections\"}} 0\n\n\
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
         velcrux_process_resident_bytes {resident_bytes}\n"
    )
}

/// Spawns the Prometheus HTTP server task.
/// Returns the bound local address and a shutdown sender to stop the metrics server gracefully.
pub async fn start_metrics_server(
    listen_addr: &str,
    stats: Arc<ServerStats>,
) -> anyhow::Result<(std::net::SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind metrics listener on {listen_addr}: {e}"))?;
    let local_addr = listener.local_addr()?;
    info!(metrics_addr = %local_addr, "Prometheus /metrics HTTP endpoint listening");

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    info!("metrics server received shutdown signal");
                    break;
                }
                accept_res = listener.accept() => {
                    let (mut socket, _) = match accept_res {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(error = %e, "metrics accept failed");
                            continue;
                        }
                    };
                    let stats = Arc::clone(&stats);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        let n = match socket.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        let req_str = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req_str.lines().next().unwrap_or("");
                        let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                        let response = if path == "/metrics" {
                            let body = format_prometheus_metrics(&stats);
                            format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                        } else if path == "/healthz" || path == "/health" || path == "/livez" {
                            let body = "healthy\n";
                            format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: text/plain\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                        } else if path == "/readyz" {
                            let is_ready = stats.is_ready.load(Ordering::Relaxed);
                            if is_ready {
                                let body = "ready\n";
                                format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: text/plain\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                            } else {
                                let body = "unready\n";
                                format!(
                                    "HTTP/1.1 503 Service Unavailable\r\n\
                                     Content-Type: text/plain\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                            }
                        } else {
                            let body = "404 Not Found\n";
                            format!(
                                "HTTP/1.1 404 Not Found\r\n\
                                 Content-Type: text/plain\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                        };

                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.shutdown().await;
                    });
                }
            }
        }
    });

    Ok((local_addr, shutdown_tx))
}
