//! Integration tests for Option K: Production Telemetry, Prometheus Metrics Exporter & Health Endpoints (`OPERATIONS.md` §5, §7).
//!
//! Verifies:
//! 1. Full Prometheus metrics text format compliance matching `OPERATIONS.md` §7.
//! 2. Health & liveness endpoints: `/healthz` and `/livez` return HTTP 200 `healthy`.
//! 3. Readiness endpoint: `/readyz` returns HTTP 200 `ready` when operational,
//!    and HTTP 503 `unready` during graceful drain / unreadiness.
//! 4. HTTP `/metrics` endpoint exports valid Prometheus text format (0.0.4).
//! 5. Proper 404 responses on unmapped paths.

#![forbid(unsafe_code)]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use velcrux_core::session::ServerStats;
use velcrux_server::metrics::{format_prometheus_metrics, start_metrics_server};

#[test]
fn test_prometheus_metrics_specification_compliance() {
    let stats = ServerStats::default();

    // Connection states
    stats.connections.store(100, Ordering::Relaxed);
    stats.connections_active.store(25, Ordering::Relaxed);
    stats.connections_closed.store(75, Ordering::Relaxed);
    stats.handshakes.store(95, Ordering::Relaxed);
    stats.pings.store(320, Ordering::Relaxed);

    // Transfers
    stats.transfers_active.store(5, Ordering::Relaxed);
    stats.transfers_active_upload.store(3, Ordering::Relaxed);
    stats.transfers_active_download.store(2, Ordering::Relaxed);
    stats.transfers_total_upload.store(50, Ordering::Relaxed);
    stats.transfers_total_download.store(40, Ordering::Relaxed);
    stats.transfers_resumable_upload.store(2, Ordering::Relaxed);
    stats
        .transfers_resumable_download
        .store(1, Ordering::Relaxed);
    stats.transfers_failed_upload.store(1, Ordering::Relaxed);
    stats.transfers_failed_download.store(0, Ordering::Relaxed);

    // Wire bytes & savings
    stats
        .bytes_transferred_upload
        .store(104857600, Ordering::Relaxed);
    stats
        .bytes_transferred_download
        .store(52428800, Ordering::Relaxed);
    stats.bytes_reused.store(20971520, Ordering::Relaxed);
    stats.bytes_saved.store(31457280, Ordering::Relaxed);

    // Throughput & transport
    stats
        .throughput_bps_upload
        .store(800_000_000, Ordering::Relaxed);
    stats
        .throughput_bps_download
        .store(600_000_000, Ordering::Relaxed);
    stats.quic_loss_ratio_ppm.store(1500, Ordering::Relaxed); // 0.0015 = 0.15%
    stats.quic_bytes_in_flight.store(1048576, Ordering::Relaxed);
    stats.last_rtt_us.store(12500, Ordering::Relaxed); // 12.5ms = 0.0125s

    // Dedup & chunk store
    stats.chunk_hits.store(80, Ordering::Relaxed);
    stats.chunk_lookups.store(100, Ordering::Relaxed);
    stats.dedup_bytes_saved.store(83886080, Ordering::Relaxed);
    stats.dedup_bytes_total.store(104857600, Ordering::Relaxed);

    // Security & limits
    stats.checksum_mismatches.store(0, Ordering::Relaxed);
    stats.checksum_mismatches_server.store(0, Ordering::Relaxed);
    stats.checksum_mismatches_client.store(0, Ordering::Relaxed);
    stats.auth_failures.store(3, Ordering::Relaxed);
    stats.authz_denials.store(4, Ordering::Relaxed);
    stats.authz_denials_read.store(1, Ordering::Relaxed);
    stats.authz_denials_write.store(3, Ordering::Relaxed);
    stats.resource_limit_hits.store(2, Ordering::Relaxed);

    // Disk I/O
    stats.disk_read_bps.store(120_000_000, Ordering::Relaxed);
    stats.disk_write_bps.store(95_000_000, Ordering::Relaxed);

    let output = format_prometheus_metrics(&stats);

    // 1. Verify connections
    assert!(output.contains("# TYPE velcrux_connections gauge"));
    assert!(output.contains("velcrux_connections{state=\"accepted\"} 100"));
    assert!(output.contains("velcrux_connections{state=\"active\"} 25"));
    assert!(output.contains("velcrux_connections{state=\"closed\"} 75"));

    // 2. Verify transfers
    assert!(output.contains("# TYPE velcrux_transfers_active gauge"));
    assert!(output.contains("velcrux_transfers_active{direction=\"bidirectional\"} 5"));
    assert!(output.contains("velcrux_transfers_active{direction=\"upload\"} 3"));
    assert!(output.contains("velcrux_transfers_active{direction=\"download\"} 2"));

    assert!(output.contains("# TYPE velcrux_transfers_total counter"));
    assert!(
        output.contains("velcrux_transfers_total{direction=\"upload\",status=\"committed\"} 50")
    );
    assert!(
        output.contains("velcrux_transfers_total{direction=\"download\",status=\"committed\"} 40")
    );
    assert!(output.contains("velcrux_transfers_total{direction=\"upload\",status=\"resumable\"} 2"));
    assert!(
        output.contains("velcrux_transfers_total{direction=\"download\",status=\"resumable\"} 1")
    );
    assert!(output.contains("velcrux_transfers_total{direction=\"upload\",status=\"failed\"} 1"));
    assert!(output.contains("velcrux_transfers_total{direction=\"download\",status=\"failed\"} 0"));

    // 3. Verify wire bytes & savings
    assert!(output.contains("velcrux_bytes_transferred_total{direction=\"upload\"} 104857600"));
    assert!(output.contains("velcrux_bytes_transferred_total{direction=\"download\"} 52428800"));
    assert!(output.contains("velcrux_bytes_reused_total 20971520"));
    assert!(output.contains("velcrux_bytes_saved_total 31457280"));

    // 4. Verify throughput & ratios
    assert!(output.contains("velcrux_throughput_bps{direction=\"upload\"} 800000000"));
    assert!(output.contains("velcrux_throughput_bps{direction=\"download\"} 600000000"));
    assert!(output.contains("velcrux_quic_loss_ratio 0.001500"));
    assert!(output.contains("velcrux_quic_bytes_in_flight 1048576"));
    assert!(output.contains("velcrux_chunk_hit_ratio 0.8000"));
    assert!(output.contains("velcrux_dedup_ratio 0.8000"));

    // 5. Verify security counters
    assert!(output.contains("velcrux_checksum_mismatch_total{side=\"server\"} 0"));
    assert!(output.contains("velcrux_auth_failures_total{reason=\"invalid_cert\"} 3"));
    assert!(output.contains("velcrux_authz_denials_total{op=\"all\"} 4"));
    assert!(output.contains("velcrux_authz_denials_total{op=\"read\"} 1"));
    assert!(output.contains("velcrux_authz_denials_total{op=\"write\"} 3"));
    assert!(output.contains("velcrux_resource_limit_hits_total{limit=\"bandwidth\"} 2"));

    // 6. Verify disk and process telemetry
    assert!(output.contains("velcrux_disk_read_bps 120000000"));
    assert!(output.contains("velcrux_disk_write_bps 95000000"));
    assert!(output.contains("# TYPE velcrux_process_cpu_seconds counter"));
    assert!(output.contains("# TYPE velcrux_process_resident_bytes gauge"));

    // 7. Verify histograms
    assert!(output.contains("# TYPE velcrux_transfer_duration_seconds histogram"));
    assert!(output.contains("velcrux_transfer_duration_seconds_bucket{le=\"+Inf\"} 90"));
    assert!(output.contains("velcrux_transfer_duration_seconds_count 90"));
    assert!(output.contains("# TYPE velcrux_rtt_seconds histogram"));
    assert!(output.contains("velcrux_rtt_seconds_bucket{le=\"+Inf\"} 1"));
    assert!(output.contains("velcrux_rtt_seconds_sum 0.012500"));
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect to metrics");
    let req = format!("GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n", path);
    stream.write_all(req.as_bytes()).await.expect("write req");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read resp");
    let resp_str = String::from_utf8_lossy(&buf).to_string();

    let status_line = resp_str.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    (status_code, resp_str)
}

#[tokio::test]
async fn test_http_health_live_ready_endpoints() {
    let stats = Arc::new(ServerStats::default());
    stats.connections.store(42, Ordering::Relaxed);

    let (addr, shutdown_tx) = start_metrics_server("127.0.0.1:0", Arc::clone(&stats))
        .await
        .expect("start metrics server");

    // Test /healthz
    let (status, body) = http_get(addr, "/healthz").await;
    assert_eq!(status, 200);
    assert!(body.ends_with("\r\n\r\nhealthy\n"));

    // Test /livez
    let (status, body) = http_get(addr, "/livez").await;
    assert_eq!(status, 200);
    assert!(body.ends_with("\r\n\r\nhealthy\n"));

    // Test /readyz when server is ready
    let (status, body) = http_get(addr, "/readyz").await;
    assert_eq!(status, 200);
    assert!(body.ends_with("\r\n\r\nready\n"));

    // Simulate graceful drain (mark server unready)
    stats.is_ready.store(false, Ordering::Relaxed);

    // Test /readyz during drain: must return HTTP 503
    let (status, body) = http_get(addr, "/readyz").await;
    assert_eq!(status, 503);
    assert!(body.ends_with("\r\n\r\nunready\n"));

    // Liveness /healthz & /livez must remain HTTP 200 healthy during drain
    let (status, body) = http_get(addr, "/livez").await;
    assert_eq!(status, 200);
    assert!(body.ends_with("\r\n\r\nhealthy\n"));

    // Test /metrics endpoint
    let (status, body) = http_get(addr, "/metrics").await;
    assert_eq!(status, 200);
    assert!(body.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"));
    assert!(body.contains("velcrux_connections{state=\"accepted\"} 42"));

    // Test 404 on unmapped endpoint
    let (status, body) = http_get(addr, "/nonexistent").await;
    assert_eq!(status, 404);
    assert!(body.contains("404 Not Found"));

    let _ = shutdown_tx.send(());
}
