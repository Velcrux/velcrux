//! Server integration tests for Bandwidth Calendar & Time-of-Day Scheduler (Option BI, `REQUIREMENTS.md` §28, `OPERATIONS.md` §43).

#![forbid(unsafe_code)]

use std::sync::Arc;
use velcrux_core::scheduler::{BandwidthRate, BandwidthSchedule, BandwidthScheduleRule};
use velcrux_core::session::ServerStats;
use velcrux_server::config::ServerConfig;
use velcrux_server::limits::LimitsManager;

#[test]
fn test_server_config_bandwidth_schedule_toml() {
    let toml_data = r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "cert.pem"
private_key = "key.pem"
client_ca = "ca.pem"

[storage]
root = "/tmp"
staging = "/tmp"

[bandwidth]
default_limit = "1Gbps"
timezone_offset_minutes = -300

[[bandwidth.rule]]
id = "biz-day"
days = "Mon-Fri"
start = "09:00"
end = "17:00"
limit = "50Mbps"

[[bandwidth.rule]]
id = "weekend"
days = "Sat,Sun"
limit = "unlimited"
"#;

    let cfg: ServerConfig = toml::from_str(toml_data).expect("parse config TOML");
    let schedule = cfg
        .bandwidth
        .build_schedule()
        .expect("build schedule")
        .expect("schedule present");

    assert_eq!(
        schedule.default_rate,
        BandwidthRate::from_bytes_per_sec(125_000_000)
    ); // 1Gbps = 125 MB/s
    assert_eq!(schedule.utc_offset_minutes, -300);
    assert_eq!(schedule.rules.len(), 2);

    assert_eq!(schedule.rules[0].id, "biz-day");
    assert_eq!(
        schedule.rules[0].rate,
        BandwidthRate::from_bytes_per_sec(6_250_000)
    ); // 50Mbps
    assert!(schedule.rules[0].time.is_some());

    assert_eq!(schedule.rules[1].id, "weekend");
    assert_eq!(schedule.rules[1].rate, BandwidthRate::UNLIMITED);
    assert!(schedule.rules[1].time.is_none());
}

#[test]
fn test_server_config_bandwidth_schedule_string_toml() {
    let toml_data = r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "cert.pem"
private_key = "key.pem"
client_ca = "ca.pem"

[storage]
root = "/tmp"
staging = "/tmp"

[bandwidth]
schedule = "Mon-Fri 09:00-17:00: 100Mbps; Sat-Sun: unlimited; default: 10Gbps"
"#;

    let cfg: ServerConfig = toml::from_str(toml_data).expect("parse config TOML");
    let schedule = cfg
        .bandwidth
        .build_schedule()
        .expect("build schedule")
        .expect("schedule present");

    assert_eq!(schedule.rules.len(), 2);
    assert_eq!(
        schedule.default_rate,
        BandwidthRate::from_bytes_per_sec(1_250_000_000)
    );
}

#[test]
fn test_server_config_bandwidth_schedule_env_override() {
    let toml_data = r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "cert.pem"
private_key = "key.pem"
client_ca = "ca.pem"

[storage]
root = "/tmp"
staging = "/tmp"
"#;

    std::env::set_var(
        "VELCRUX_BANDWIDTH_SCHEDULE",
        "Mon-Fri: 200Mbps; default: 5Gbps",
    );
    let mut cfg: ServerConfig = toml::from_str(toml_data).expect("parse config TOML");
    cfg.apply_env_overrides();
    std::env::remove_var("VELCRUX_BANDWIDTH_SCHEDULE");

    let schedule = cfg
        .bandwidth
        .build_schedule()
        .expect("build schedule")
        .expect("schedule present");
    assert_eq!(schedule.rules.len(), 1);
    assert_eq!(
        schedule.default_rate,
        BandwidthRate::from_bytes_per_sec(625_000_000)
    );
}

#[tokio::test]
async fn test_limits_manager_with_bandwidth_schedule() {
    let stats = Arc::new(ServerStats::default());
    let mut sched = BandwidthSchedule::new(BandwidthRate::from_bytes_per_sec(100_000_000)); // 100 MB/s default
    sched.add_rule(BandwidthScheduleRule {
        id: "day-cap".into(),
        days: velcrux_core::DayMatcher::All,
        time: None,
        rate: BandwidthRate::from_bytes_per_sec(10_000_000), // 10 MB/s
        description: "all day test rule".into(),
    });

    let manager = LimitsManager::new(Some("1Gbps"), Some(10), None, None, &[], Arc::clone(&stats))
        .expect("create limits manager")
        .with_schedule(Some(Arc::new(sched)));

    assert!(manager.schedule().is_some());
    // Schedule rule matches all day, so effective rate should be 10 MB/s = 10,000,000 bytes/sec
    assert_eq!(manager.effective_global_bandwidth(), 10_000_000);
}

#[tokio::test]
async fn test_limits_manager_schedule_hot_reload() {
    let stats = Arc::new(ServerStats::default());
    let manager = Arc::new(
        LimitsManager::new(
            Some("10Gbps"),
            Some(100),
            None,
            None,
            &[],
            Arc::clone(&stats),
        )
        .expect("create limits manager"),
    );

    assert!(manager.schedule().is_none());

    // Hot reload with a dynamic schedule
    let mut sched = BandwidthSchedule::new(BandwidthRate::from_bytes_per_sec(50_000_000));
    sched.add_rule(BandwidthScheduleRule {
        id: "night-surge".into(),
        days: velcrux_core::DayMatcher::All,
        time: None,
        rate: BandwidthRate::from_bytes_per_sec(200_000_000),
        description: "overnight fast throughput".into(),
    });

    manager
        .reload_with_schedule(
            Some("10Gbps"),
            Some(100),
            None,
            None,
            &[],
            Some(Arc::new(sched)),
        )
        .expect("reload with schedule");

    assert!(manager.schedule().is_some());
    assert_eq!(manager.effective_global_bandwidth(), 200_000_000);

    // Dynamic runtime update via set_schedule
    manager.set_schedule(None);
    assert!(manager.schedule().is_none());
}
