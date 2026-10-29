//! Integration tests for Option CE: eBPF-Driven Programmable L7 Proxying
//! & Dynamic Layer-7 Load Shedding (`ADR-047`).

#![forbid(unsafe_code)]

use std::process::Command;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_proxy_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("status")
        .output()
        .expect("execute proxy status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Programmable L7 Proxy & Load Shedder Status ==="));
    assert!(stdout.contains("Pressure Score:"));
    assert!(stdout.contains("Policy Mode:"));
    assert!(stdout.contains("Active Flows:"));
    assert!(stdout.contains("Active Rules:"));

    // 2. JSON output with simulated high pressure
    let json_out = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("status")
        .arg("--cpu")
        .arg("85.0")
        .arg("--mem")
        .arg("80.0")
        .arg("--queue")
        .arg("75.0")
        .arg("--json")
        .output()
        .expect("execute proxy status json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).expect("parse status json");
    assert!(v["pressure_score_pct"].as_f64().unwrap() > 60.0);
    assert_eq!(v["default_policy_mode"], "heavy_tier_shedding");
}

#[test]
fn test_cli_proxy_rules_text_and_json() {
    // 1. Text table
    let output = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("rules")
        .output()
        .expect("execute proxy rules");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Active Programmable L7 Proxy Rules ==="));
    assert!(stdout.contains("default-control-admit"));
    assert!(stdout.contains("premium-tier-fastpath"));
    assert!(stdout.contains("cold-archive-reroute"));

    // 2. JSON rules list
    let json_out = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("rules")
        .arg("--json")
        .output()
        .expect("execute proxy rules json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).expect("parse rules json");
    assert!(v["count"].as_u64().unwrap() >= 3);
    assert_eq!(v["rules"][0]["id"], "default-control-admit");
}

#[test]
fn test_cli_proxy_add_rule() {
    let output = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("add-rule")
        .arg("--id")
        .arg("custom-throttle-corp")
        .arg("--desc")
        .arg("Rate limit corp tenant")
        .arg("--precedence")
        .arg("15")
        .arg("--tenant-prefix")
        .arg("tenant-corp")
        .arg("--action")
        .arg("throttle")
        .arg("--json")
        .output()
        .expect("execute proxy add-rule");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse add-rule json");
    assert_eq!(v["success"], true);
    assert_eq!(v["rule"]["id"], "custom-throttle-corp");
    assert_eq!(v["rule"]["precedence"], 15);
}

#[test]
fn test_cli_proxy_classify_flows() {
    // 1. Control flow classification (strictly admitted)
    let ctrl_out = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("classify")
        .arg("--tenant")
        .arg("tenant-standard")
        .arg("--path")
        .arg("/control/cancel")
        .arg("--stream-type")
        .arg("control")
        .arg("--pressure")
        .arg("99.0")
        .arg("--json")
        .output()
        .expect("classify control");

    assert!(ctrl_out.status.success());
    let v_ctrl: serde_json::Value = serde_json::from_slice(&ctrl_out.stdout).unwrap();
    assert_eq!(v_ctrl["flow_tier"], "control");
    assert_eq!(v_ctrl["decision_action"]["action"], "admit");

    // 2. Background flow classification under critical pressure (must be shed)
    let bg_out = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("classify")
        .arg("--tenant")
        .arg("tenant-standard")
        .arg("--path")
        .arg("/archive/bulk-backup.tar")
        .arg("--stream-type")
        .arg("data")
        .arg("--flow-priority")
        .arg("8")
        .arg("--pressure")
        .arg("95.0")
        .arg("--json")
        .output()
        .expect("classify background");

    assert!(bg_out.status.success());
    let v_bg: serde_json::Value = serde_json::from_slice(&bg_out.stdout).unwrap();
    assert_eq!(v_bg["flow_tier"], "background");
    assert_eq!(v_bg["decision_action"]["action"], "shed");
}

#[test]
fn test_cli_proxy_load_shedding_cascade() {
    let output = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("shed")
        .arg("--pressure")
        .arg("85.0")
        .arg("--json")
        .output()
        .expect("execute proxy shed");

    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse shed json");
    assert_eq!(v["policy_mode"], "heavy_tier_shedding");

    let tiers = v["tiers"].as_array().expect("tiers array");
    assert_eq!(tiers.len(), 5);

    // Control must be ADMITTED
    assert_eq!(tiers[0]["tier"], "Control");
    assert_eq!(tiers[0]["verdict"], "ADMITTED");

    // Background must be SHED at 85%
    assert_eq!(tiers[4]["tier"], "Background");
    assert_eq!(tiers[4]["verdict"], "SHED");

    // BulkLow must be THROTTLED at 85%
    assert_eq!(tiers[3]["tier"], "BulkLow");
    assert_eq!(tiers[3]["verdict"], "THROTTLED");
}

#[test]
fn test_cli_proxy_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("proxy")
        .arg("benchmark")
        .arg("--iterations")
        .arg("100")
        .arg("--json")
        .output()
        .expect("execute proxy benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse benchmark json");
    assert_eq!(v["iterations"], 100);
    assert_eq!(v["all_verdicts_correct"], true);
    assert!(v["throughput_ops_per_second"].as_f64().unwrap() > 0.0);
    assert!(v["flows_admitted"].as_u64().unwrap() > 0);
    assert!(v["flows_shed"].as_u64().unwrap() > 0);
}
