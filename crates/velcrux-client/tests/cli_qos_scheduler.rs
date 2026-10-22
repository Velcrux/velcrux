//! Integration tests for Option BU: Hierarchical Token-Bucket Quality of Service (QoS)
//! & Flow Priority Multiplexer (`ADR-037`).

#![forbid(unsafe_code)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use velcrux_core::scheduler::{
    fairness::BandwidthRate, HierarchicalQosScheduler, QosBand, QosClass, QosFlowMultiplexer,
};
use velcrux_core::util::TransferId;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_qos_inspect_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("qos")
        .arg("inspect")
        .arg("--bandwidth")
        .arg("1Gbps")
        .output()
        .expect("execute qos inspect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Hierarchical Token-Bucket (HTB) QoS Inspection ==="));
    assert!(stdout.contains("Root Bandwidth Ceiling:  1Gbps"));
    assert!(stdout.contains("realtime"));
    assert!(stdout.contains("critical"));
    assert!(stdout.contains("default"));
    assert!(stdout.contains("background"));
    assert!(stdout.contains("40.0%"));
    assert!(stdout.contains("35.0%"));
    assert!(stdout.contains("20.0%"));
    assert!(stdout.contains("5.0%"));

    // 2. JSON output
    let output_json = Command::new(velcrux_bin())
        .arg("qos")
        .arg("inspect")
        .arg("--bandwidth")
        .arg("500Mbps")
        .arg("--json")
        .output()
        .expect("execute qos inspect json");

    assert!(output_json.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("parse json qos inspect");
    assert_eq!(v["root_bandwidth"], "500Mbps");
    let allocs = v["allocations"].as_array().expect("allocations array");
    assert_eq!(allocs.len(), 4);
    assert_eq!(allocs[0]["class"], "realtime");
    assert_eq!(allocs[0]["weight"], 8);
    assert_eq!(allocs[1]["class"], "critical");
    assert_eq!(allocs[1]["weight"], 4);
}

#[test]
fn test_cli_qos_benchmark_text_and_json() {
    // 1. Text benchmark output
    let output = Command::new(velcrux_bin())
        .arg("qos")
        .arg("benchmark")
        .arg("--bandwidth")
        .arg("100Mbps")
        .arg("--packets")
        .arg("50")
        .output()
        .expect("execute qos benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Hierarchical QoS Flow Contention Benchmark ==="));
    assert!(stdout.contains("CIR Isolation Verified:  true"));
    assert!(stdout.contains("Per-Class Distribution:"));
    assert!(stdout.contains("Realtime:"));
    assert!(stdout.contains("Critical:"));
    assert!(stdout.contains("Default:"));
    assert!(stdout.contains("Background:"));

    // 2. JSON benchmark output
    let output_json = Command::new(velcrux_bin())
        .arg("qos")
        .arg("benchmark")
        .arg("--bandwidth")
        .arg("200Mbps")
        .arg("--packets")
        .arg("40")
        .arg("--json")
        .output()
        .expect("execute qos benchmark json");

    assert!(output_json.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("parse json benchmark");
    assert_eq!(report["root_bandwidth"], "200Mbps");
    assert_eq!(report["cir_isolation_verified"], true);
    assert!(report["total_bytes_admitted"].as_u64().unwrap() > 0);
    assert!(report["realtime_bytes"].as_u64().unwrap() > 0);
    assert!(report["critical_bytes"].as_u64().unwrap() > 0);
    assert!(report["default_bytes"].as_u64().unwrap() > 0);
    assert!(report["background_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_qos_status_flags_and_json() {
    // 1. Default status
    let output = Command::new(velcrux_bin())
        .arg("qos")
        .arg("status")
        .output()
        .expect("execute qos status");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Active QoS & Flow Multiplexing Status ==="));
    assert!(stdout.contains("Priority Tier:           default"));
    assert!(stdout.contains("Scheduling Weight:       2"));
    assert!(stdout.contains("CIR Guaranteed Fraction: 20.0%"));

    // 2. Custom priority and bandwidth via global flags in JSON
    let output_custom = Command::new(velcrux_bin())
        .arg("--qos-priority")
        .arg("critical")
        .arg("--qos-bandwidth")
        .arg("10Gbps")
        .arg("qos")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute qos status custom");

    assert!(output_custom.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&output_custom.stdout).expect("parse status json");
    assert_eq!(v["qos_priority"], "critical");
    assert_eq!(v["weight"], 4);
    assert_eq!(v["cir_fraction"], 0.35);
    assert_eq!(v["root_bandwidth"], "10Gbps");
}

#[test]
fn test_scheduler_borrowing_and_isolation() {
    let root_rate = BandwidthRate::from_bps(80_000_000); // 10 MB/s
    let scheduler = HierarchicalQosScheduler::new(root_rate);

    // Guaranteed rates:
    // Realtime: 40% (4 MB/s)
    // Critical: 35% (3.5 MB/s)
    // Default: 20% (2 MB/s)
    // Background: 5% (0.5 MB/s)

    // Evaluate small admission
    let adm = scheduler.evaluate_admission(QosClass::Critical, None, 16 * 1024);
    assert!(adm.admitted);
    assert_eq!(adm.delay(), Duration::ZERO);

    // Configure tenant band with strict CIR and PIR
    let tenant_band = QosBand::new(
        "tenant-sla",
        QosClass::Critical,
        BandwidthRate::from_bps(20_000_000), // 2.5 MB/s CIR
        BandwidthRate::from_bps(60_000_000), // 7.5 MB/s PIR
    );
    scheduler.configure_tenant("tenant-sla", tenant_band);

    let adm_tenant =
        scheduler.evaluate_admission(QosClass::Critical, Some("tenant-sla"), 32 * 1024);
    assert!(adm_tenant.admitted);

    let stats = scheduler.stats();
    assert!(
        stats
            .tokens_consumed_total
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 48 * 1024
    );
}

#[test]
fn test_flow_multiplexer_strict_priority_and_wrr() {
    let scheduler = Arc::new(HierarchicalQosScheduler::new(BandwidthRate::UNLIMITED));
    let mux = QosFlowMultiplexer::new(scheduler);

    let tid = TransferId::generate();

    // Enqueue: 2 Realtime, 5 Critical, 3 Default, 2 Background
    mux.enqueue("rt-1".to_string(), QosClass::Realtime, "t1", tid, 100);
    mux.enqueue("rt-2".to_string(), QosClass::Realtime, "t1", tid, 100);
    for i in 0..5 {
        mux.enqueue(format!("crit-{i}"), QosClass::Critical, "t1", tid, 100);
    }
    for i in 0..3 {
        mux.enqueue(format!("def-{i}"), QosClass::Default, "t1", tid, 100);
    }
    for i in 0..2 {
        mux.enqueue(format!("bg-{i}"), QosClass::Background, "t1", tid, 100);
    }

    // First two items MUST be Realtime
    let item1 = mux.dequeue().expect("rt1");
    assert_eq!(item1.class, QosClass::Realtime);
    assert_eq!(item1.item, "rt-1");

    let item2 = mux.dequeue().expect("rt2");
    assert_eq!(item2.class, QosClass::Realtime);
    assert_eq!(item2.item, "rt-2");

    // Next 4 items in WRR cycle: Critical steps 0..=3
    let item3 = mux.dequeue().expect("crit0");
    assert_eq!(item3.class, QosClass::Critical);
    let item4 = mux.dequeue().expect("crit1");
    assert_eq!(item4.class, QosClass::Critical);
    let item5 = mux.dequeue().expect("crit2");
    assert_eq!(item5.class, QosClass::Critical);
    let item6 = mux.dequeue().expect("crit3");
    assert_eq!(item6.class, QosClass::Critical);

    // Next 2 items in WRR cycle: Default steps 4..=5
    let item7 = mux.dequeue().expect("def0");
    assert_eq!(item7.class, QosClass::Default);
    let item8 = mux.dequeue().expect("def1");
    assert_eq!(item8.class, QosClass::Default);

    // Next 1 item in WRR cycle: Background step 6
    let item9 = mux.dequeue().expect("bg0");
    assert_eq!(item9.class, QosClass::Background);
}
