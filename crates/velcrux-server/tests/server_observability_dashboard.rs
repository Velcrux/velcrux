//! Integration tests for Option AA: Production Prometheus Metrics & Observability Suite
//! (`OPERATIONS.md` §7, `REQUIREMENTS.md` §14, §83, `docs/METRICS.md`).
//!
//! Verifies:
//! 1. Metrics Catalog Completeness: Every metric emitted by `format_prometheus_metrics` is documented in `docs/METRICS.md`.
//! 2. Grafana Dashboard JSON Integrity: Dashboard conforms to Grafana schema, contains valid panel layouts, and references valid `velcrux_*` metrics.
//! 3. Prometheus Alert Rules Syntax: Alert rules YAML contains valid structure, required labels, annotations, and PromQL targets.
//! 4. CLI Exporter Subcommands: `velcruxd export-dashboard` and `velcruxd export-alerts` accurately dump canonical definitions.
//! 5. Live HTTP Scrape: `/metrics` endpoint serves valid Prometheus text format (0.0.4) over HTTP/1.1.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use velcrux_core::session::ServerStats;
use velcrux_server::metrics::{
    format_prometheus_metrics, grafana_dashboard_json, prometheus_alerts_yaml, start_metrics_server,
};

// ---------------------------------------------------------------------------
// 1. Metric Documentation Catalog Completeness
// ---------------------------------------------------------------------------

#[test]
fn test_metrics_doc_catalog_completeness() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let metrics_doc_path = root.join("docs").join("METRICS.md");
    assert!(
        metrics_doc_path.is_file(),
        "docs/METRICS.md must exist in repository"
    );

    let doc_content = fs::read_to_string(&metrics_doc_path).expect("read docs/METRICS.md");

    // Populate all stats so every metric family is rendered
    let stats = ServerStats::default();
    stats.connections.store(10, Ordering::Relaxed);
    stats.transfers_active.store(2, Ordering::Relaxed);
    stats.transfers_total_upload.store(5, Ordering::Relaxed);
    stats
        .bytes_transferred_upload
        .store(1024, Ordering::Relaxed);
    stats
        .throughput_bps_upload
        .store(100_000, Ordering::Relaxed);
    stats.chunk_hits.store(5, Ordering::Relaxed);
    stats.chunk_lookups.store(10, Ordering::Relaxed);
    stats.dedup_bytes_saved.store(500, Ordering::Relaxed);
    stats.dedup_bytes_total.store(1000, Ordering::Relaxed);
    stats.auth_failures.store(1, Ordering::Relaxed);
    stats.authz_denials.store(1, Ordering::Relaxed);
    stats.resource_limit_hits.store(1, Ordering::Relaxed);
    stats.disk_read_bps.store(5000, Ordering::Relaxed);
    stats.disk_write_bps.store(5000, Ordering::Relaxed);

    let rendered = format_prometheus_metrics(&stats);

    // Extract all distinct metric names from rendered output
    let mut metric_names = Vec::new();
    for line in rendered.lines() {
        if line.starts_with("# HELP ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                metric_names.push(parts[2]);
            }
        }
    }

    assert!(
        !metric_names.is_empty(),
        "Rendered metrics must have HELP declarations"
    );

    for name in metric_names {
        assert!(
            doc_content.contains(name),
            "Metric '{name}' emitted by velcrux-server must be documented in docs/METRICS.md"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Grafana Dashboard JSON Integrity & Panel Coverage
// ---------------------------------------------------------------------------

#[test]
fn test_grafana_dashboard_json_validity_and_coverage() {
    let dashboard_raw = grafana_dashboard_json();
    let dashboard: serde_json::Value =
        serde_json::from_str(dashboard_raw).expect("Dashboard must be valid JSON");

    // Top-level schema assertions
    assert_eq!(
        dashboard["uid"], "velcrux-overview",
        "UID must be velcrux-overview"
    );
    assert_eq!(
        dashboard["title"], "Velcrux Storage Node Overview",
        "Title must match standard"
    );
    let schema_ver = dashboard["schemaVersion"]
        .as_i64()
        .expect("schemaVersion must be integer");
    assert!(
        schema_ver >= 36,
        "Dashboard schemaVersion must be modern (>= 36)"
    );

    let panels = dashboard["panels"]
        .as_array()
        .expect("panels must be an array");
    assert!(
        panels.len() >= 10,
        "Dashboard must contain rich set of panels (found {})",
        panels.len()
    );

    // Ensure all metric expressions query velcrux_* metrics
    let mut queried_metrics = Vec::new();
    for p in panels {
        if let Some(targets) = p["targets"].as_array() {
            for t in targets {
                if let Some(expr) = t["expr"].as_str() {
                    assert!(
                        expr.contains("velcrux_"),
                        "Panel expression '{expr}' must query velcrux_* metric"
                    );
                    for token in expr.split(|c: char| !c.is_alphanumeric() && c != '_') {
                        if token.starts_with("velcrux_") {
                            queried_metrics.push(token.to_string());
                        }
                    }
                }
            }
        }
    }

    assert!(
        !queried_metrics.is_empty(),
        "Dashboard must query at least one velcrux metric"
    );
    assert!(
        queried_metrics.iter().any(|m| m.contains("throughput")),
        "Dashboard must monitor throughput"
    );
    assert!(
        queried_metrics.iter().any(|m| m.contains("transfers")),
        "Dashboard must monitor transfers"
    );
}

// ---------------------------------------------------------------------------
// 3. Prometheus Alert Rules Syntax & Quality
// ---------------------------------------------------------------------------

#[test]
fn test_prometheus_alerts_yaml_validity() {
    let alerts_raw = prometheus_alerts_yaml();

    assert!(alerts_raw.contains("groups:"), "Must declare groups");
    assert!(
        alerts_raw.contains("- name: velcrux-alerts"),
        "Must declare velcrux-alerts group"
    );
    assert!(alerts_raw.contains("rules:"), "Must declare rules");

    let mut alert_count = 0;
    let mut current_alert = String::new();
    let mut has_expr = false;
    let mut has_severity = false;
    let mut has_summary = false;

    for line in alerts_raw.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("- alert:") {
            if !current_alert.is_empty() {
                assert!(has_expr, "Alert '{current_alert}' must have an expr");
                assert!(
                    has_severity,
                    "Alert '{current_alert}' must have a severity label"
                );
                assert!(
                    has_summary,
                    "Alert '{current_alert}' must have a summary annotation"
                );
            }
            current_alert = name.trim().to_string();
            assert!(!current_alert.is_empty());
            alert_count += 1;
            has_expr = false;
            has_severity = false;
            has_summary = false;
        } else if let Some(expr) = trimmed.strip_prefix("expr:") {
            assert!(
                expr.contains("velcrux_"),
                "Alert expr '{expr}' must query velcrux_* metrics"
            );
            has_expr = true;
        } else if let Some(sev) = trimmed.strip_prefix("severity:") {
            let s = sev.trim();
            assert!(
                s == "critical" || s == "warning" || s == "info",
                "Severity '{s}' must be valid"
            );
            has_severity = true;
        } else if trimmed.starts_with("summary:") {
            has_summary = true;
        }
    }

    if !current_alert.is_empty() {
        assert!(has_expr, "Alert '{current_alert}' must have an expr");
        assert!(
            has_severity,
            "Alert '{current_alert}' must have a severity label"
        );
        assert!(
            has_summary,
            "Alert '{current_alert}' must have a summary annotation"
        );
    }

    assert!(
        alert_count >= 5,
        "Must declare at least 5 alerts (found {alert_count})"
    );
}

// ---------------------------------------------------------------------------
// 4. CLI Subcommand Export Functionality
// ---------------------------------------------------------------------------

#[test]
fn test_cli_export_subcommands() {
    let td = tempdir().unwrap();
    let dashboard_out = td.path().join("exported_dashboard.json");
    let alerts_out = td.path().join("exported_alerts.yml");

    let bin_path = env!("CARGO_BIN_EXE_velcruxd");

    // Test export-dashboard to file
    let status_dash = Command::new(bin_path)
        .args(["export-dashboard", "--out", dashboard_out.to_str().unwrap()])
        .status()
        .expect("run export-dashboard");
    assert!(status_dash.success(), "export-dashboard should exit 0");
    assert!(
        dashboard_out.is_file(),
        "Exported dashboard file must exist"
    );
    let dash_content = fs::read_to_string(&dashboard_out).unwrap();
    assert_eq!(dash_content, grafana_dashboard_json());

    // Test export-alerts to file
    let status_alerts = Command::new(bin_path)
        .args(["export-alerts", "--out", alerts_out.to_str().unwrap()])
        .status()
        .expect("run export-alerts");
    assert!(status_alerts.success(), "export-alerts should exit 0");
    assert!(alerts_out.is_file(), "Exported alerts file must exist");
    let alerts_content = fs::read_to_string(&alerts_out).unwrap();
    assert_eq!(alerts_content, prometheus_alerts_yaml());

    // Test export-dashboard to stdout
    let stdout_dash = Command::new(bin_path)
        .arg("export-dashboard")
        .output()
        .expect("run export-dashboard to stdout");
    assert!(stdout_dash.status.success());
    let stdout_dash_str = String::from_utf8(stdout_dash.stdout).unwrap();
    assert_eq!(stdout_dash_str, grafana_dashboard_json());

    // Test export-alerts to stdout
    let stdout_alerts = Command::new(bin_path)
        .arg("export-alerts")
        .output()
        .expect("run export-alerts to stdout");
    assert!(stdout_alerts.status.success());
    let stdout_alerts_str = String::from_utf8(stdout_alerts.stdout).unwrap();
    assert_eq!(stdout_alerts_str, prometheus_alerts_yaml());
}

// ---------------------------------------------------------------------------
// 5. Live HTTP Scrape & Prometheus Text Format 0.0.4 Verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_live_http_metrics_scrape_and_format() {
    let stats = Arc::new(ServerStats::default());
    stats.connections.store(42, Ordering::Relaxed);
    stats.transfers_active.store(3, Ordering::Relaxed);
    stats
        .bytes_transferred_upload
        .store(999_999, Ordering::Relaxed);

    let (addr, shutdown_tx) = start_metrics_server("127.0.0.1:0", stats)
        .await
        .expect("start live metrics server");

    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to metrics endpoint");
    let req = format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();

    let _ = shutdown_tx.send(());

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"));
    assert!(resp.contains("velcrux_connections{state=\"accepted\"} 42"));
    assert!(resp.contains("velcrux_transfers_active{direction=\"bidirectional\"} 3"));
    assert!(resp.contains("velcrux_bytes_transferred_total{direction=\"upload\"} 999999"));
}
