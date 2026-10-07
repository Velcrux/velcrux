//! Embedded REST Control Plane, Operator Management API & Live Telemetry Dashboard
//! (`REQUIREMENTS.md` §36, §38, §81, `OPERATIONS.md` §6, §7).
//!
//! Exposes:
//! - REST API v1 (`/api/v1/status`, `/api/v1/sessions`, `/api/v1/sessions/kill`, `/api/v1/quotas`, `/api/v1/gc`)
//! - Live Single-Page Operator Dashboard (`/` and `/dashboard`)
//! - Prometheus `/metrics` and Kubernetes `/healthz`, `/livez`, `/readyz` probes
//! - Backward-compatible administrative endpoints (`/admin/sessions`, `/admin/kill-session`)

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{info, warn};

use velcrux_core::session::ServerStats;
use velcrux_core::storage::{gc_chunk_store, gc_staging, ChunkStoreGcReport, StagingGcReport};

use crate::limits::{LimitsManager, TenantQuotaInfo};
use crate::metrics::format_prometheus_metrics;
use crate::sessions::SessionRegistry;

/// Comprehensive daemon status response (`REQUIREMENTS.md` §36, §38).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub listen_address: String,
    pub is_ready: bool,
    pub connections_active: u64,
    pub connections_total: u64,
    pub transfers_active: u64,
    pub transfers_active_upload: u64,
    pub transfers_active_download: u64,
    pub transfers_committed_upload: u64,
    pub transfers_committed_download: u64,
    pub throughput_upload_bps: u64,
    pub throughput_download_bps: u64,
    pub bytes_transferred_upload: u64,
    pub bytes_transferred_download: u64,
    pub bytes_saved_total: u64,
    pub bytes_reused_total: u64,
    pub dedup_ratio: f64,
    pub chunk_hit_ratio: f64,
    pub quic_loss_ratio: f64,
    pub quic_bytes_in_flight: u64,
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
    pub process_cpu_seconds: f64,
    pub process_resident_bytes: u64,
}

/// On-demand garbage collection response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcResponse {
    pub dry_run: bool,
    pub staging: Option<StagingGcReport>,
    pub chunk_store: Option<ChunkStoreGcReport>,
    pub total_bytes_reclaimed: u64,
}

/// Session kill response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSessionResponse {
    pub killed: usize,
}

/// Shared runtime context for the API server.
#[derive(Clone)]
pub struct ApiServerContext {
    pub stats: Arc<ServerStats>,
    pub registry: Option<Arc<SessionRegistry>>,
    pub limits_mgr: Option<Arc<LimitsManager>>,
    pub storage_root: Option<PathBuf>,
    pub staging_root: Option<PathBuf>,
    pub state_db_path: Option<PathBuf>,
    pub chunk_store_path: Option<PathBuf>,
    pub listen_addr: String,
    pub started_at: Instant,
}

impl ApiServerContext {
    pub fn new(stats: Arc<ServerStats>, listen_addr: String) -> Self {
        Self {
            stats,
            registry: None,
            limits_mgr: None,
            storage_root: None,
            staging_root: None,
            state_db_path: None,
            chunk_store_path: None,
            listen_addr,
            started_at: Instant::now(),
        }
    }

    pub fn with_registry(mut self, registry: Option<Arc<SessionRegistry>>) -> Self {
        self.registry = registry;
        self
    }

    pub fn with_limits(mut self, limits_mgr: Option<Arc<LimitsManager>>) -> Self {
        self.limits_mgr = limits_mgr;
        self
    }

    pub fn with_paths(
        mut self,
        storage_root: Option<PathBuf>,
        staging_root: Option<PathBuf>,
        state_db_path: Option<PathBuf>,
        chunk_store_path: Option<PathBuf>,
    ) -> Self {
        self.storage_root = storage_root;
        self.staging_root = staging_root;
        self.state_db_path = state_db_path;
        self.chunk_store_path = chunk_store_path;
        self
    }
}

/// Safely sample process CPU time (in seconds) and resident memory (in bytes).
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

/// Build the server status payload from live statistics.
pub fn build_status_response(ctx: &ApiServerContext) -> ServerStatusResponse {
    let stats = &ctx.stats;
    let conns_total = stats.connections.load(Ordering::Relaxed);
    let conns_active = stats.connections_active.load(Ordering::Relaxed);

    let active = stats.transfers_active.load(Ordering::Relaxed);
    let active_up = stats.transfers_active_upload.load(Ordering::Relaxed);
    let active_down = stats.transfers_active_download.load(Ordering::Relaxed);

    let committed_up = stats.transfers_total_upload.load(Ordering::Relaxed);
    let committed_down = stats.transfers_total_download.load(Ordering::Relaxed);

    let throughput_up = stats.throughput_bps_upload.load(Ordering::Relaxed);
    let throughput_down = stats.throughput_bps_download.load(Ordering::Relaxed);

    let bytes_up = stats.bytes_transferred_upload.load(Ordering::Relaxed);
    let bytes_down = stats.bytes_transferred_download.load(Ordering::Relaxed);

    let bytes_saved = stats.bytes_saved.load(Ordering::Relaxed);
    let bytes_reused = stats.bytes_reused.load(Ordering::Relaxed);

    let dedup_saved = stats.dedup_bytes_saved.load(Ordering::Relaxed);
    let dedup_total = stats.dedup_bytes_total.load(Ordering::Relaxed);
    let dedup_ratio = if dedup_total > 0 {
        dedup_saved as f64 / dedup_total as f64
    } else {
        0.0
    };

    let chunk_hits = stats.chunk_hits.load(Ordering::Relaxed);
    let chunk_lookups = stats.chunk_lookups.load(Ordering::Relaxed);
    let chunk_hit_ratio = if chunk_lookups > 0 {
        chunk_hits as f64 / chunk_lookups as f64
    } else {
        0.0
    };

    let loss_ratio = stats.quic_loss_ratio_ppm.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let bytes_in_flight = stats.quic_bytes_in_flight.load(Ordering::Relaxed);

    let disk_read_bps = stats.disk_read_bps.load(Ordering::Relaxed);
    let disk_write_bps = stats.disk_write_bps.load(Ordering::Relaxed);

    let (cpu_seconds, resident_bytes) = sample_process_metrics();
    let is_ready = stats.is_ready.load(Ordering::Relaxed);

    ServerStatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: ctx.started_at.elapsed().as_secs(),
        listen_address: ctx.listen_addr.clone(),
        is_ready,
        connections_active: conns_active,
        connections_total: conns_total,
        transfers_active: active,
        transfers_active_upload: active_up,
        transfers_active_download: active_down,
        transfers_committed_upload: committed_up,
        transfers_committed_download: committed_down,
        throughput_upload_bps: throughput_up,
        throughput_download_bps: throughput_down,
        bytes_transferred_upload: bytes_up,
        bytes_transferred_download: bytes_down,
        bytes_saved_total: bytes_saved,
        bytes_reused_total: bytes_reused,
        dedup_ratio,
        chunk_hit_ratio,
        quic_loss_ratio: loss_ratio,
        quic_bytes_in_flight: bytes_in_flight,
        disk_read_bps,
        disk_write_bps,
        process_cpu_seconds: cpu_seconds,
        process_resident_bytes: resident_bytes,
    }
}

/// Parse query string into a key-value mapping.
fn parse_query(query: &str) -> Vec<(&str, &str)> {
    let mut params = Vec::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.push((k, v));
        } else if !pair.is_empty() {
            params.push((pair, ""));
        }
    }
    params
}

/// Dispatch and format HTTP responses for the management control plane.
pub async fn handle_request(ctx: &ApiServerContext, req: &str) -> String {
    let first_line = req.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let full_path = parts.next().unwrap_or("/");

    let (path, query) = if let Some((p, q)) = full_path.split_once('?') {
        (p, q)
    } else {
        (full_path, "")
    };

    // CORS preflight handling
    if method == "OPTIONS" {
        return "HTTP/1.1 204 No Content\r\n\
                Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n\
                Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
                Content-Length: 0\r\n\
                Connection: close\r\n\r\n"
            .to_string();
    }

    // 1. Prometheus metrics endpoint
    if path == "/metrics" {
        let body = format_prometheus_metrics(&ctx.stats);
        return format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
    }

    // 2. Health & Liveness probes
    if path == "/healthz" || path == "/health" || path == "/livez" {
        let body = "healthy\n";
        return format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
    }

    // 3. Readiness probe
    if path == "/readyz" {
        let is_ready = ctx.stats.is_ready.load(Ordering::Relaxed);
        return if is_ready {
            let body = "ready\n";
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Access-Control-Allow-Origin: *\r\n\
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
                 Access-Control-Allow-Origin: *\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            )
        };
    }

    // 4. REST API: Node Status
    if path == "/api/v1/status" {
        let status = build_status_response(ctx);
        let body = serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".into());
        return format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
    }

    // 5. REST API: Active Sessions list
    if path == "/api/v1/sessions" || path == "/admin/sessions" {
        let sessions = if let Some(reg) = &ctx.registry {
            reg.list_sessions().await
        } else {
            Vec::new()
        };
        let body = serde_json::to_string_pretty(&sessions).unwrap_or_else(|_| "[]".into());
        return format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
    }

    // 6. REST API: Terminate Session
    if path == "/api/v1/sessions/kill"
        || path.starts_with("/admin/kill-session")
        || (path == "/api/v1/sessions" && (method == "DELETE" || method == "POST"))
    {
        let mut killed = 0;
        let query_params = parse_query(query);

        if let Some(reg) = &ctx.registry {
            for (k, v) in query_params {
                if k == "identity" {
                    killed += reg.kill_by_identity(v).await;
                } else if k == "conn_id" {
                    if let Ok(id) = v.parse::<u64>() {
                        if reg.kill_by_conn_id(id).await {
                            killed += 1;
                        }
                    }
                }
            }
        }

        let resp = KillSessionResponse { killed };
        let body = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into());
        return format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
    }

    // 7. REST API: Tenant Quotas
    if path == "/api/v1/quotas" {
        let quotas: Vec<TenantQuotaInfo> = if let Some(mgr) = &ctx.limits_mgr {
            mgr.list_tenants_quotas()
        } else {
            Vec::new()
        };
        let body = serde_json::to_string_pretty(&quotas).unwrap_or_else(|_| "[]".into());
        return format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
    }

    // 8. REST API: Garbage Collection Trigger
    if path == "/api/v1/gc" {
        let query_params = parse_query(query);
        let mut dry_run = false;
        let mut run_staging = true;
        let mut run_chunks = true;

        for (k, v) in query_params {
            match k {
                "dry_run" => dry_run = v == "true" || v == "1",
                "staging" => run_staging = v == "true" || v == "1",
                "chunks" => run_chunks = v == "true" || v == "1",
                _ => {}
            }
        }

        let mut staging_rep = None;
        let mut chunk_rep = None;
        let mut total_reclaimed = 0u64;

        if run_staging {
            if let Some(staging_dir) = &ctx.staging_root {
                let state_db = ctx.state_db_path.clone().unwrap_or_else(|| {
                    staging_dir
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .join("state.db")
                });
                if state_db.exists() && staging_dir.exists() {
                    if let Ok(state_store) = velcrux_core::SqliteStateStore::new(&state_db) {
                        if let Ok(rep) = gc_staging(staging_dir, &state_store, dry_run) {
                            total_reclaimed = total_reclaimed.saturating_add(rep.bytes_reclaimed);
                            staging_rep = Some(rep);
                        }
                    }
                }
            }
        }

        if run_chunks {
            if let Some(storage_dir) = &ctx.storage_root {
                let chunk_path = ctx.chunk_store_path.clone().unwrap_or_else(|| {
                    storage_dir
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .join("chunks")
                });
                if chunk_path.exists() {
                    if let Ok(cs) = velcrux_core::LocalChunkStore::new(&chunk_path).await {
                        if let Ok(rep) = gc_chunk_store(&cs, &[storage_dir], dry_run) {
                            total_reclaimed = total_reclaimed.saturating_add(rep.bytes_reclaimed);
                            chunk_rep = Some(rep);
                        }
                    }
                }
            }
        }

        let resp = GcResponse {
            dry_run,
            staging: staging_rep,
            chunk_store: chunk_rep,
            total_bytes_reclaimed: total_reclaimed,
        };

        let body = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into());
        return format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );
    }

    // 9. Live Web Dashboard
    if path == "/" || path == "/dashboard" {
        let html = render_dashboard_html();
        return format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            html.len(),
            html
        );
    }

    // 404 Not Found fallback
    let body = "{\"error\": \"not found\"}\n";
    format!(
        "HTTP/1.1 404 Not Found\r\n\
         Content-Type: application/json\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// Spawns the unified API and metrics HTTP server.
pub async fn start_api_server(
    ctx: ApiServerContext,
) -> anyhow::Result<(SocketAddr, oneshot::Sender<()>)> {
    let listen_addr = &ctx.listen_addr;
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind api listener on {listen_addr}: {e}"))?;
    let local_addr = listener.local_addr()?;
    info!(
        api_addr = %local_addr,
        "Velcrux Control Plane & Telemetry Dashboard listening"
    );

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    info!("api server received shutdown signal");
                    break;
                }
                accept_res = listener.accept() => {
                    let (mut socket, _) = match accept_res {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(error = %e, "api accept failed");
                            continue;
                        }
                    };
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let n = match socket.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        let req_str = String::from_utf8_lossy(&buf[..n]);
                        let response = handle_request(&ctx, &req_str).await;

                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.shutdown().await;
                    });
                }
            }
        }
    });

    Ok((local_addr, shutdown_tx))
}

/// Self-contained Single-Page Application Dashboard (HTML5/CSS3/Vanilla JS).
/// Zero CDN or third-party web requests — 100% operational in air-gapped data centers.
pub fn render_dashboard_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Velcrux Control Plane</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111726;
      --card-border: rgba(56, 189, 248, 0.15);
      --card-hover: rgba(56, 189, 248, 0.25);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --primary-glow: rgba(56, 189, 248, 0.25);
      --accent: #818cf8;
      --success: #34d399;
      --warning: #fbbf24;
      --danger: #f43f5e;
      --table-header: #172033;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      padding: 24px;
      line-height: 1.5;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
    }
    .brand { display: flex; align-items: center; gap: 14px; }
    .logo {
      width: 40px; height: 40px;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-weight: 800; font-size: 20px; color: #fff;
      box-shadow: 0 0 20px var(--primary-glow);
    }
    .title h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
    .title p { font-size: 13px; color: var(--text-muted); }
    .header-actions { display: flex; align-items: center; gap: 12px; }
    .badge-pulse {
      display: inline-flex; align-items: center; gap: 8px;
      background: rgba(52, 211, 153, 0.12);
      border: 1px solid rgba(52, 211, 153, 0.3);
      color: var(--success);
      padding: 6px 14px; border-radius: 20px;
      font-size: 13px; font-weight: 600;
    }
    .pulse-dot {
      width: 8px; height: 8px; background: var(--success);
      border-radius: 50%; box-shadow: 0 0 8px var(--success);
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
    .btn-link {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
      color: var(--text); padding: 7px 14px;
      border-radius: 8px; text-decoration: none;
      font-size: 13px; font-weight: 500;
      transition: all 0.2s ease;
    }
    .btn-link:hover { background: rgba(56, 189, 248, 0.15); border-color: var(--primary); }

    /* Stats Grid */
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 18px; margin-bottom: 24px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px; padding: 20px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .card:hover { transform: translateY(-2px); border-color: var(--card-hover); }
    .card-label { font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.5px; }
    .card-value { font-size: 28px; font-weight: 700; color: #fff; margin: 8px 0 4px 0; }
    .card-sub { font-size: 13px; color: var(--text-muted); display: flex; justify-content: space-between; }

    /* Sections */
    .section-title { font-size: 17px; font-weight: 600; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between; }
    .table-container {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px; overflow: hidden;
      margin-bottom: 24px;
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
    th { background: var(--table-header); color: var(--text-muted); font-weight: 600; padding: 14px 18px; border-bottom: 1px solid var(--card-border); }
    td { padding: 14px 18px; border-bottom: 1px solid rgba(255,255,255,0.05); }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .btn-danger {
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid rgba(244, 63, 94, 0.4);
      color: #fda4af; padding: 6px 12px;
      border-radius: 6px; cursor: pointer;
      font-size: 12px; font-weight: 600;
      transition: all 0.2s;
    }
    .btn-danger:hover { background: rgba(244, 63, 94, 0.3); border-color: var(--danger); }
    .btn-primary {
      background: linear-gradient(135deg, var(--primary), var(--accent));
      border: none; color: #fff;
      padding: 9px 18px; border-radius: 8px;
      cursor: pointer; font-size: 13px; font-weight: 600;
      box-shadow: 0 0 15px var(--primary-glow);
      transition: all 0.2s;
    }
    .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
    .gc-box {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px; padding: 22px;
      display: flex; justify-content: space-between;
      align-items: center; flex-wrap: gap: 16px;
    }
    .status-msg { font-size: 13px; color: var(--success); margin-top: 6px; font-weight: 500; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="logo">V</div>
        <div class="title">
          <h1>Velcrux Control Plane</h1>
          <p id="listen-addr">Loading endpoint...</p>
        </div>
      </div>
      <div class="header-actions">
        <div class="badge-pulse"><span class="pulse-dot"></span>ONLINE</div>
        <a href="/metrics" class="btn-link" target="_blank">Prometheus /metrics</a>
        <a href="/api/v1/status" class="btn-link" target="_blank">Status JSON</a>
      </div>
    </header>

    <!-- Metrics Cards -->
    <div class="grid">
      <div class="card">
        <div class="card-label">Active Connections</div>
        <div class="card-value" id="val-conns">0</div>
        <div class="card-sub"><span>Total Handshakes</span><span id="val-conns-total">0</span></div>
      </div>
      <div class="card">
        <div class="card-label">Live Throughput (Up / Down)</div>
        <div class="card-value" id="val-tp">0 / 0 Mbps</div>
        <div class="card-sub"><span>Bytes Out / In</span><span id="val-bytes-total">0 / 0 MB</span></div>
      </div>
      <div class="card">
        <div class="card-label">Active Transfers</div>
        <div class="card-value" id="val-transfers">0</div>
        <div class="card-sub"><span>Committed (Up/Down)</span><span id="val-transfers-comm">0 / 0</span></div>
      </div>
      <div class="card">
        <div class="card-label">Storage Saved (Dedup/Sparse)</div>
        <div class="card-value" id="val-saved">0 MB</div>
        <div class="card-sub"><span>Dedup Ratio</span><span id="val-dedup-ratio">0.0%</span></div>
      </div>
    </div>

    <!-- Active Sessions -->
    <div class="section-title">
      <span>Active Client Sessions</span>
      <span style="font-size: 13px; color: var(--text-muted);" id="session-count">0 sessions active</span>
    </div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Connection ID</th>
            <th>Identity</th>
            <th>Remote Address</th>
            <th>Uptime</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="sessions-tbody">
          <tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No active client sessions</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Tenant Quotas -->
    <div class="section-title">
      <span>Tenant Storage & Bandwidth Quotas</span>
    </div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Tenant Identity</th>
            <th>Storage Usage</th>
            <th>Transfer Quota</th>
            <th>Reserved In-Flight</th>
            <th>Max Bandwidth</th>
          </tr>
        </thead>
        <tbody id="quotas-tbody">
          <tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No tenant quotas registered</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Maintenance Panel -->
    <div class="section-title">
      <span>Disk Maintenance & Garbage Collection</span>
    </div>
    <div class="gc-box">
      <div>
        <h3 style="font-size: 16px; margin-bottom: 4px;">Content-Addressed Storage Pruning</h3>
        <p style="font-size: 13px; color: var(--text-muted);">Reclaim disk space by cleaning unreferenced chunk store extents and orphaned staging directories.</p>
        <div class="status-msg" id="gc-result"></div>
      </div>
      <button class="btn-primary" onclick="triggerGc()">Run Garbage Collection</button>
    </div>
  </div>

  <script>
    function fmtBytes(b) {
      if (b === 0) return '0 B';
      const k = 1024;
      const dm = 2;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(b) / Math.log(k));
      return parseFloat((b / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    function fmtBps(b) {
      const mbps = (b / 1000000).toFixed(2);
      return mbps + ' Mbps';
    }

    async function updateDashboard() {
      try {
        const [resStatus, resSessions, resQuotas] = await Promise.all([
          fetch('/api/v1/status'),
          fetch('/api/v1/sessions'),
          fetch('/api/v1/quotas')
        ]);

        if (resStatus.ok) {
          const s = await resStatus.json();
          document.getElementById('listen-addr').innerText = 'Listen Address: ' + s.listen_address + ' • Uptime: ' + s.uptime_seconds + 's • v' + s.version;
          document.getElementById('val-conns').innerText = s.connections_active;
          document.getElementById('val-conns-total').innerText = s.connections_total;
          document.getElementById('val-tp').innerText = fmtBps(s.throughput_upload_bps) + ' / ' + fmtBps(s.throughput_download_bps);
          document.getElementById('val-bytes-total').innerText = fmtBytes(s.bytes_transferred_upload) + ' / ' + fmtBytes(s.bytes_transferred_download);
          document.getElementById('val-transfers').innerText = s.transfers_active;
          document.getElementById('val-transfers-comm').innerText = s.transfers_committed_upload + ' / ' + s.transfers_committed_download;
          document.getElementById('val-saved').innerText = fmtBytes(s.bytes_saved_total);
          document.getElementById('val-dedup-ratio').innerText = (s.dedup_ratio * 100).toFixed(1) + '%';
        }

        if (resSessions.ok) {
          const sessions = await resSessions.json();
          document.getElementById('session-count').innerText = sessions.length + ' sessions active';
          const tbody = document.getElementById('sessions-tbody');
          if (sessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No active client sessions</td></tr>';
          } else {
            tbody.innerHTML = sessions.map(sess => `
              <tr>
                <td><strong>#${sess.conn_id}</strong></td>
                <td>${sess.identity || '<em style="color:var(--text-muted)">Unauthenticated</em>'}</td>
                <td><code>${sess.remote_addr}</code></td>
                <td>${sess.uptime_secs}s</td>
                <td><button class="btn-danger" onclick="killSession(${sess.conn_id})">Terminate</button></td>
              </tr>
            `).join('');
          }
        }

        if (resQuotas.ok) {
          const quotas = await resQuotas.json();
          const qbody = document.getElementById('quotas-tbody');
          if (quotas.length === 0) {
            qbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No tenant quotas registered</td></tr>';
          } else {
            qbody.innerHTML = quotas.map(q => `
              <tr>
                <td><strong>${q.identity}</strong></td>
                <td>${fmtBytes(q.storage_usage_bytes)}</td>
                <td>${fmtBytes(q.transfer_usage_bytes)}${q.quota_bytes ? ' / ' + fmtBytes(q.quota_bytes) : ' (Unlimited)'}</td>
                <td>${fmtBytes(q.reserved_bytes)}</td>
                <td>${q.max_bandwidth_bps ? fmtBps(q.max_bandwidth_bps) : 'Unlimited'}</td>
              </tr>
            `).join('');
          }
        }
      } catch (e) {
        console.error('Failed to poll dashboard telemetry', e);
      }
    }

    async function killSession(connId) {
      try {
        const res = await fetch(`/api/v1/sessions/kill?conn_id=${connId}`, { method: 'POST' });
        if (res.ok) {
          updateDashboard();
        }
      } catch (e) {
        alert('Failed to terminate session: ' + e);
      }
    }

    async function triggerGc() {
      const status = document.getElementById('gc-result');
      status.innerText = 'Executing garbage collection sweep...';
      try {
        const res = await fetch('/api/v1/gc', { method: 'POST' });
        if (res.ok) {
          const r = await res.json();
          status.innerText = `Sweep completed! Reclaimed ${fmtBytes(r.total_bytes_reclaimed)} of disk space.`;
          updateDashboard();
        } else {
          status.innerText = 'Failed to execute GC.';
        }
      } catch (e) {
        status.innerText = 'Error running GC: ' + e;
      }
    }

    setInterval(updateDashboard, 2000);
    updateDashboard();
  </script>
</body>
</html>"#
}
