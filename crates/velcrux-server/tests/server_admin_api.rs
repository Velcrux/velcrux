//! Integration tests for Milestone Option AG:
//! Embedded REST Control Plane, Operator Management API & Live Telemetry Dashboard
//! (`REQUIREMENTS.md` §36, §38, §81, `OPERATIONS.md` §6, §7).

#![forbid(unsafe_code)]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;

use velcrux_core::session::ServerStats;
use velcrux_server::api::{
    handle_request, start_api_server, ApiServerContext, GcResponse, ServerStatusResponse,
};
use velcrux_server::config::LimitsCfg;
use velcrux_server::limits::LimitsManager;
use velcrux_server::sessions::SessionRegistry;

#[tokio::test]
async fn test_rest_control_plane_and_dashboard_handlers() {
    let stats = Arc::new(ServerStats::default());
    stats.connections.store(42, Ordering::Relaxed);
    stats.connections_active.store(3, Ordering::Relaxed);
    stats.transfers_active.store(2, Ordering::Relaxed);
    stats
        .throughput_bps_upload
        .store(15_000_000, Ordering::Relaxed);
    stats.is_ready.store(true, Ordering::Relaxed);

    let registry = SessionRegistry::new();
    let temp = tempdir().unwrap();
    let storage_root = temp.path().join("files");
    let staging_root = temp.path().join("staging");
    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let limits_cfg = vec![LimitsCfg {
        identity: "tenant-alice".to_string(),
        max_bandwidth: Some("100Mbps".to_string()),
        quota_bytes: Some("10MiB".to_string()),
        soft_quota_bytes: Some("8MiB".to_string()),
    }];

    let limits_mgr = Arc::new(
        LimitsManager::new(
            Some("1Gbps"),
            Some(100),
            Some(10),
            Some(20),
            &limits_cfg,
            Arc::clone(&stats),
        )
        .expect("create limits manager"),
    );

    let ctx = ApiServerContext::new(Arc::clone(&stats), "127.0.0.1:9443".to_string())
        .with_registry(Some(Arc::clone(&registry)))
        .with_limits(Some(Arc::clone(&limits_mgr)))
        .with_paths(Some(storage_root), Some(staging_root), None, None);

    // 1. Test Node Status endpoint (/api/v1/status)
    let resp = handle_request(&ctx, "GET /api/v1/status HTTP/1.1\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("Content-Type: application/json"));
    let json_body = resp.split("\r\n\r\n").nth(1).unwrap();
    let status: ServerStatusResponse = serde_json::from_str(json_body).expect("parse status json");
    assert_eq!(status.connections_total, 42);
    assert_eq!(status.connections_active, 3);
    assert_eq!(status.transfers_active, 2);
    assert_eq!(status.throughput_upload_bps, 15_000_000);
    assert!(status.is_ready);

    // 2. Test Active Sessions listing (/api/v1/sessions)
    let peer_addr: std::net::SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let kill_rx = registry.register(101, peer_addr).await;
    registry.set_identity(101, "client-bob").await;

    let resp_sess = handle_request(&ctx, "GET /api/v1/sessions HTTP/1.1\r\n\r\n").await;
    assert!(resp_sess.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_sess.contains("client-bob"));
    assert!(resp_sess.contains("101"));

    // 3. Test Kill Session (/api/v1/sessions/kill?conn_id=101)
    let resp_kill = handle_request(
        &ctx,
        "POST /api/v1/sessions/kill?conn_id=101 HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(resp_kill.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_kill.contains("\"killed\": 1"));
    assert!(*kill_rx.borrow(), "kill signal should have fired");

    // 4. Test Tenant Quotas (/api/v1/quotas)
    let resp_quotas = handle_request(&ctx, "GET /api/v1/quotas HTTP/1.1\r\n\r\n").await;
    assert!(resp_quotas.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_quotas.contains("tenant-alice"));
    assert!(resp_quotas.contains("10485760")); // 10 MiB quota

    // 5. Test Garbage Collection trigger (/api/v1/gc)
    let resp_gc = handle_request(&ctx, "POST /api/v1/gc?dry_run=true HTTP/1.1\r\n\r\n").await;
    assert!(resp_gc.starts_with("HTTP/1.1 200 OK"));
    let gc_body = resp_gc.split("\r\n\r\n").nth(1).unwrap();
    let gc_res: GcResponse = serde_json::from_str(gc_body).expect("parse gc response");
    assert!(gc_res.dry_run);

    // 6. Test Web Dashboard (/dashboard and /)
    let resp_dash = handle_request(&ctx, "GET /dashboard HTTP/1.1\r\n\r\n").await;
    assert!(resp_dash.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_dash.contains("Content-Type: text/html; charset=utf-8"));
    assert!(resp_dash.contains("Velcrux Control Plane"));
    assert!(resp_dash.contains("Active Client Sessions"));

    let resp_root = handle_request(&ctx, "GET / HTTP/1.1\r\n\r\n").await;
    assert!(resp_root.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_root.contains("Velcrux Control Plane"));

    // 7. Test Prometheus /metrics and Health Probes
    let resp_metrics = handle_request(&ctx, "GET /metrics HTTP/1.1\r\n\r\n").await;
    assert!(resp_metrics.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_metrics.contains("velcrux_connections"));

    let resp_health = handle_request(&ctx, "GET /healthz HTTP/1.1\r\n\r\n").await;
    assert!(resp_health.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_health.contains("healthy"));

    let resp_ready = handle_request(&ctx, "GET /readyz HTTP/1.1\r\n\r\n").await;
    assert!(resp_ready.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_ready.contains("ready"));

    // 8. Test CORS OPTIONS
    let resp_options = handle_request(&ctx, "OPTIONS /api/v1/status HTTP/1.1\r\n\r\n").await;
    assert!(resp_options.starts_with("HTTP/1.1 204 No Content"));
    assert!(resp_options.contains("Access-Control-Allow-Origin: *"));

    // 9. Test 404 on Unknown Path
    let resp_404 = handle_request(&ctx, "GET /api/v1/nonexistent HTTP/1.1\r\n\r\n").await;
    assert!(resp_404.starts_with("HTTP/1.1 404 Not Found"));
    assert!(resp_404.contains("not found"));
}

#[tokio::test]
async fn test_api_server_bind_and_shutdown() {
    let stats = Arc::new(ServerStats::default());
    let ctx = ApiServerContext::new(stats, "127.0.0.1:0".to_string());
    let (_addr, shutdown_tx) = start_api_server(ctx).await.expect("bind api server");
    let _ = shutdown_tx.send(());
}
