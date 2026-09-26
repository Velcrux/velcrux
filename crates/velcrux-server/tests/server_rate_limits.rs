//! Comprehensive test suite for Option O: Bandwidth Metering & Multi-Tenant Rate Limiting Enforcement.
//!
//! Verifies:
//! 1. Human-readable bandwidth (`10Gbps`, `500MiB`, `unlimited`) and quota (`10GiB`, `unlimited`) parsing.
//! 2. Hierarchical token bucket rate limiting (tenant limit chained to global server bandwidth cap).
//! 3. Tenant quota enforcement (rejection with `ErrorCode::QuotaExceeded`).
//! 4. SIGHUP hot-reload of `LimitsManager` preserving accumulated tenant quota usage.
//! 5. Connection ceiling enforcement and Prometheus metrics export (`velcrux_resource_limit_hits_total`).

#![forbid(unsafe_code)]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use velcrux_core::error::ProtocolError;
use velcrux_core::parse_rate_limit;
use velcrux_core::session::ServerStats;
use velcrux_core::transfer::rate_limit::RateLimiter;
use velcrux_server::config::{LimitsCfg, ServerConfig};
use velcrux_server::limits::LimitsManager;
use velcrux_server::metrics::format_prometheus_metrics;

#[test]
fn test_bandwidth_string_parsing() {
    assert_eq!(parse_rate_limit("10Gbps").unwrap(), 10_000_000_000);
    assert_eq!(parse_rate_limit("1Gbps").unwrap(), 1_000_000_000);
    assert_eq!(parse_rate_limit("100MB/s").unwrap(), 100_000_000);
    assert_eq!(parse_rate_limit("500MiB").unwrap(), 500 * 1024 * 1024);
    assert_eq!(parse_rate_limit("256KiB").unwrap(), 256 * 1024);
    assert_eq!(parse_rate_limit("unlimited").unwrap(), 0);
    assert_eq!(parse_rate_limit("0").unwrap(), 0);
    assert!(parse_rate_limit("invalid-bw").is_err());
}

#[test]
fn test_quota_string_parsing() {
    assert_eq!(parse_rate_limit("10GiB").unwrap(), 10 * 1024 * 1024 * 1024);
    assert_eq!(parse_rate_limit("500MiB").unwrap(), 500 * 1024 * 1024);
    assert_eq!(parse_rate_limit("100MB").unwrap(), 100 * 1_000_000);
    assert_eq!(parse_rate_limit("1GiB").unwrap(), 1024 * 1024 * 1024);
    assert_eq!(parse_rate_limit("unlimited").unwrap(), 0);
    assert_eq!(parse_rate_limit("0").unwrap(), 0);
    assert!(parse_rate_limit("invalid-quota").is_err());
}

#[tokio::test]
async fn test_hierarchical_rate_limiter_tokens() {
    let stats = Arc::new(ServerStats::default());
    let hit_counter = Arc::clone(&stats.resource_limit_hits_bandwidth);

    // Global limiter: 100 KB/s
    let global_limiter =
        Arc::new(RateLimiter::new(100_000).with_hit_counter(Arc::clone(&hit_counter)));

    // Tenant limiter: 50 KB/s with global as parent
    let tenant_limiter = RateLimiter::new(50_000)
        .with_parent(Arc::clone(&global_limiter))
        .with_hit_counter(Arc::clone(&hit_counter));

    // First acquire within burst should succeed immediately
    let t0 = std::time::Instant::now();
    tenant_limiter.acquire(10_000).await;
    assert!(t0.elapsed() < Duration::from_millis(100));

    // Consuming more tokens than available will trigger throttle wait and increment hit counter
    tenant_limiter.acquire(300_000).await;
    assert!(hit_counter.load(Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn test_limits_manager_quota_enforcement_and_metrics() {
    let stats = Arc::new(ServerStats::default());
    let limits_cfg = vec![
        LimitsCfg {
            identity: "tenant-capped".into(),
            max_bandwidth: Some("100MB/s".into()),
            quota_bytes: Some("100KiB".into()),
        },
        LimitsCfg {
            identity: "tenant-unlimited".into(),
            max_bandwidth: None,
            quota_bytes: None,
        },
    ];

    let manager = LimitsManager::new(Some("10Gbps"), Some(10), &limits_cfg, Arc::clone(&stats))
        .expect("create limits manager");

    // 1. Unlimited tenant can request large size without quota error
    let unlim_res = manager.check_quota(Some("tenant-unlimited"), 10 * 1024 * 1024);
    assert!(unlim_res.is_ok());

    // 2. Capped tenant requesting 60 KiB succeeds (< 100 KiB quota)
    let ok_res = manager.check_quota(Some("tenant-capped"), 60 * 1024);
    assert!(ok_res.is_ok());

    // Record the 60 KiB usage
    manager.record_transfer(Some("tenant-capped"), 60 * 1024);

    // 3. Capped tenant requesting another 50 KiB (total 110 KiB > 100 KiB quota) fails with QuotaExceeded
    let exceed_res = manager.check_quota(Some("tenant-capped"), 50 * 1024);
    assert!(exceed_res.is_err());
    let err_msg = exceed_res.unwrap_err();
    assert!(err_msg.contains("quota exceeded"));

    // Verify stats counter incremented
    assert_eq!(stats.resource_limit_hits_quota.load(Ordering::Relaxed), 1);

    // Verify Prometheus metrics export includes quota hit
    let prometheus = format_prometheus_metrics(&stats);
    assert!(prometheus.contains("velcrux_resource_limit_hits_total{limit=\"quota\"} 1"));
}

#[tokio::test]
async fn test_limits_manager_connection_ceiling_and_metrics() {
    let stats = Arc::new(ServerStats::default());
    let manager = LimitsManager::new(None, Some(2), &[], Arc::clone(&stats))
        .expect("create limits manager with max 2 connections");

    // 0 active conns: allowed
    assert!(manager.check_connection_limit(0).is_ok());
    // 1 active conn: allowed
    assert!(manager.check_connection_limit(1).is_ok());
    // 2 active conns (at limit): rejected
    assert!(manager.check_connection_limit(2).is_err());
    // 3 active conns: rejected
    assert!(manager.check_connection_limit(3).is_err());

    // 2 rejections above should increment connections hit counter by 2
    assert_eq!(
        stats
            .resource_limit_hits_connections
            .load(Ordering::Relaxed),
        2
    );

    let prometheus = format_prometheus_metrics(&stats);
    assert!(prometheus.contains("velcrux_resource_limit_hits_total{limit=\"connections\"} 2"));
}

#[tokio::test]
async fn test_limits_manager_sighup_reload_preserves_usage() {
    let stats = Arc::new(ServerStats::default());
    let initial_limits = vec![LimitsCfg {
        identity: "tenant-dyn".into(),
        max_bandwidth: Some("10MB/s".into()),
        quota_bytes: Some("100KiB".into()),
    }];

    let manager = LimitsManager::new(Some("1Gbps"), Some(10), &initial_limits, Arc::clone(&stats))
        .expect("create initial manager");

    // Record 80 KiB usage for tenant-dyn
    manager.record_transfer(Some("tenant-dyn"), 80 * 1024);

    // Reload with expanded quota (200 KiB)
    let reloaded_limits = vec![LimitsCfg {
        identity: "tenant-dyn".into(),
        max_bandwidth: Some("50MB/s".into()),
        quota_bytes: Some("200KiB".into()),
    }];

    manager
        .reload(Some("2Gbps"), &reloaded_limits)
        .expect("reload limits manager");

    // Accumulated 80 KiB usage should be preserved:
    // Requesting 100 KiB (80 + 100 = 180 <= 200) should now succeed!
    assert!(manager.check_quota(Some("tenant-dyn"), 100 * 1024).is_ok());

    // Requesting 150 KiB (80 + 150 = 230 > 200) should fail
    assert!(manager.check_quota(Some("tenant-dyn"), 150 * 1024).is_err());
}

#[tokio::test]
async fn test_config_validation_for_limits() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("server.toml");
    let state_db = temp.path().join("state.db");

    let invalid_bw_toml = format!(
        r#"
[network]
listen = "127.0.0.1:7443"
max_bandwidth = "invalid-unit"

[security]
certificate = "/tmp/server.crt"
private_key = "/tmp/server.key"
client_ca   = "/tmp/ca.crt"

[storage]
root     = "/tmp/storage"
staging  = "/tmp/staging"
state_db = "{}"
"#,
        state_db.display()
    );

    std::fs::write(&config_path, invalid_bw_toml).unwrap();
    assert!(ServerConfig::load(&config_path).is_err());

    let invalid_quota_toml = format!(
        r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "/tmp/server.crt"
private_key = "/tmp/server.key"
client_ca   = "/tmp/ca.crt"

[storage]
root     = "/tmp/storage"
staging  = "/tmp/staging"
state_db = "{}"

[[limits]]
identity = "tenant1"
quota_bytes = "not-a-number"
"#,
        state_db.display()
    );

    std::fs::write(&config_path, invalid_quota_toml).unwrap();
    assert!(ServerConfig::load(&config_path).is_err());
}

#[test]
fn test_error_detail_maps_quota_exceeded() {
    let err = ProtocolError::QuotaExceeded("exceeded 100MiB cap".into());
    let detail = velcrux_core::protocol::error::ErrorDetail::from(err);
    assert_eq!(detail.0, "quota exceeded");
}
