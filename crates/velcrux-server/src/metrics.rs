//! Prometheus metrics exporter HTTP server (`OPERATIONS.md` §7).
//!
//! Exposes `/metrics` in standard Prometheus text format (`0.0.4`) and `/healthz`
//! on the configured `telemetry.metrics_listen` address.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{info, warn};
use velcrux_core::session::ServerStats;

/// Format current server statistics as Prometheus metrics text.
pub fn format_prometheus_metrics(stats: &ServerStats) -> String {
    let conns = stats.connections.load(Ordering::Relaxed);
    let handshakes = stats.handshakes.load(Ordering::Relaxed);
    let pings = stats.pings.load(Ordering::Relaxed);
    let active = stats.transfers_active.load(Ordering::Relaxed);
    let uploads = stats.transfers_total_upload.load(Ordering::Relaxed);
    let downloads = stats.transfers_total_download.load(Ordering::Relaxed);
    let bytes_up = stats.bytes_transferred_upload.load(Ordering::Relaxed);
    let bytes_down = stats.bytes_transferred_download.load(Ordering::Relaxed);
    let bytes_reused = stats.bytes_reused.load(Ordering::Relaxed);
    let authz_denials = stats.authz_denials.load(Ordering::Relaxed);
    let checksum_mismatches = stats.checksum_mismatches.load(Ordering::Relaxed);

    format!(
        "# HELP velcrux_connections Total connections accepted\n\
         # TYPE velcrux_connections counter\n\
         velcrux_connections{{state=\"accepted\"}} {conns}\n\n\
         # HELP velcrux_handshakes_total Total completed handshakes\n\
         # TYPE velcrux_handshakes_total counter\n\
         velcrux_handshakes_total {handshakes}\n\n\
         # HELP velcrux_pings_total Total pings handled\n\
         # TYPE velcrux_pings_total counter\n\
         velcrux_pings_total {pings}\n\n\
         # HELP velcrux_transfers_active Currently active transfers\n\
         # TYPE velcrux_transfers_active gauge\n\
         velcrux_transfers_active{{direction=\"bidirectional\"}} {active}\n\n\
         # HELP velcrux_transfers_total Total completed transfers\n\
         # TYPE velcrux_transfers_total counter\n\
         velcrux_transfers_total{{direction=\"upload\",status=\"committed\"}} {uploads}\n\
         velcrux_transfers_total{{direction=\"download\",status=\"committed\"}} {downloads}\n\n\
         # HELP velcrux_bytes_transferred_total Total bytes transferred over wire\n\
         # TYPE velcrux_bytes_transferred_total counter\n\
         velcrux_bytes_transferred_total{{direction=\"upload\"}} {bytes_up}\n\
         velcrux_bytes_transferred_total{{direction=\"download\"}} {bytes_down}\n\n\
         # HELP velcrux_bytes_reused_total Total bytes reused from existing storage\n\
         # TYPE velcrux_bytes_reused_total counter\n\
         velcrux_bytes_reused_total {bytes_reused}\n\n\
         # HELP velcrux_authz_denials_total Total authorization denials\n\
         # TYPE velcrux_authz_denials_total counter\n\
         velcrux_authz_denials_total{{op=\"all\"}} {authz_denials}\n\n\
         # HELP velcrux_checksum_mismatch_total Total checksum mismatches detected\n\
         # TYPE velcrux_checksum_mismatch_total counter\n\
         velcrux_checksum_mismatch_total{{side=\"server\"}} {checksum_mismatches}\n"
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
                        } else if path == "/healthz" || path == "/health" {
                            let body = "healthy\n";
                            format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: text/plain\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
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
