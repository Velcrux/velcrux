//! Integration tests for Bandwidth Calendar & Time-of-Day Scheduler CLI (Option BI, `REQUIREMENTS.md` §28, `OPERATIONS.md` §43).

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
fn test_cli_schedule_inspect_human() {
    let output = Command::new(velcrux_bin())
        .arg("schedule")
        .arg("inspect")
        .arg("--schedule")
        .arg("Mon-Fri 09:00-17:00: 50Mbps # Business hours; Sat,Sun: unlimited # Weekend boost; default: 1Gbps")
        .output()
        .expect("execute velcrux schedule inspect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("BANDWIDTH CALENDAR SCHEDULE INSPECTION"));
    assert!(stdout.contains("Default Rate         : 1Gbps"));
    assert!(stdout.contains("Configured Rules     : 2"));
    assert!(stdout.contains("Mon-Fri"));
    assert!(stdout.contains("09:00-17:00"));
    assert!(stdout.contains("50Mbps"));
    assert!(stdout.contains("Sat,Sun"));
    assert!(stdout.contains("CURRENT EVALUATION"));
    assert!(stdout.contains("Next Transition In"));
}

#[test]
fn test_cli_schedule_inspect_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("schedule")
        .arg("inspect")
        .arg("--schedule")
        .arg("[id=peak] Mon-Fri 08:30-17:30: 25Mbps; default: 500Mbps")
        .output()
        .expect("execute velcrux --json schedule inspect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("valid JSON expected from --json schedule inspect");

    assert_eq!(json_val["event"], "schedule_inspect");
    assert_eq!(json_val["schedule"]["default_rate"], "500Mbps");
    let rules = json_val["schedule"]["rules"]
        .as_array()
        .expect("rules array");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "peak");
    assert_eq!(rules[0]["days"], "Mon-Fri");
    assert_eq!(rules[0]["time_window"], "08:30-17:30");
    assert_eq!(rules[0]["rate"], "25Mbps");

    let active = &json_val["schedule"]["active_status"];
    assert!(active["active_rate"].is_string());
    assert!(active["active_rate_bps"].is_number());
    assert!(active["seconds_until_transition"].is_number());
}

#[test]
fn test_cli_schedule_eval_human() {
    // 1776162000 is Tuesday 10:20:00 UTC (Weekday business hours)
    let tue_10_20_utc = 1776162000u64;

    let output = Command::new(velcrux_bin())
        .arg("schedule")
        .arg("eval")
        .arg("--schedule")
        .arg("[id=work] Mon-Fri 09:00-17:00: 100Mbps; default: 10Gbps")
        .arg("--timestamp")
        .arg(tue_10_20_utc.to_string())
        .arg("--utc-offset")
        .arg("0")
        .output()
        .expect("execute velcrux schedule eval");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("BANDWIDTH SCHEDULE EVALUATION"));
    assert!(stdout.contains("Active Rate Limit    : 100Mbps"));
    assert!(stdout.contains("Matching Source      : Rule \"work\""));
}

#[test]
fn test_cli_schedule_eval_json_business_vs_offpeak() {
    let schedule = "[id=biz] Mon-Fri 09:00-17:00: 50Mbps; default: 1Gbps";

    // Tuesday 10:00 UTC -> inside business hours (50Mbps)
    let tue_10_00 = 1776160800u64;
    let out_biz = Command::new(velcrux_bin())
        .arg("--json")
        .arg("schedule")
        .arg("eval")
        .arg("--schedule")
        .arg(schedule)
        .arg("--timestamp")
        .arg(tue_10_00.to_string())
        .output()
        .expect("eval biz hours");

    assert!(out_biz.status.success());
    let j_biz: serde_json::Value = serde_json::from_slice(&out_biz.stdout).unwrap();
    assert_eq!(j_biz["event"], "schedule_eval");
    assert_eq!(j_biz["evaluation"]["active_rate"], "50Mbps");
    assert_eq!(j_biz["evaluation"]["matching_rule_id"], "biz");
    assert_eq!(j_biz["evaluation"]["is_default"], false);

    // Tuesday 20:00 UTC -> outside business hours (1Gbps default)
    let tue_20_00 = 1776196800u64;
    let out_off = Command::new(velcrux_bin())
        .arg("--json")
        .arg("schedule")
        .arg("eval")
        .arg("--schedule")
        .arg(schedule)
        .arg("--timestamp")
        .arg(tue_20_00.to_string())
        .output()
        .expect("eval off-peak hours");

    assert!(out_off.status.success());
    let j_off: serde_json::Value = serde_json::from_slice(&out_off.stdout).unwrap();
    assert_eq!(j_off["event"], "schedule_eval");
    assert_eq!(j_off["evaluation"]["active_rate"], "1Gbps");
    assert_eq!(j_off["evaluation"]["is_default"], true);
}

#[test]
fn test_cli_schedule_file_loading() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let file_path = dir.path().join("policy.sched");
    std::fs::write(
        &file_path,
        "Mon-Fri 08:00-18:00: 10Mbps # strict day cap\nSat-Sun: 2Gbps\ndefault: 500Mbps\n",
    )
    .expect("write sched file");

    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("schedule")
        .arg("inspect")
        .arg("--schedule")
        .arg(file_path.to_str().unwrap())
        .output()
        .expect("inspect file schedule");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let j: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(j["schedule"]["rules"].as_array().unwrap().len(), 2);
    assert_eq!(j["schedule"]["default_rate"], "500Mbps");
}

#[test]
fn test_cli_schedule_global_flag() {
    let output = Command::new(velcrux_bin())
        .arg("--bandwidth-schedule")
        .arg("Weekdays 09:00-17:00: 75Mbps; default: 2.5Gbps")
        .arg("--json")
        .arg("schedule")
        .arg("inspect")
        .output()
        .expect("inspect via global flag");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let j: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(j["schedule"]["default_rate"], "2500Mbps");
    assert_eq!(j["schedule"]["rules"][0]["rate"], "75Mbps");
}

#[test]
fn test_cli_schedule_overnight_window() {
    // Overnight window: 22:00 to 06:00
    // Tuesday 23:30 (overnight active)
    let tue_23_30 = 1776209400u64;
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("schedule")
        .arg("eval")
        .arg("--schedule")
        .arg("22:00-06:00: 10Gbps; default: 100Mbps")
        .arg("--timestamp")
        .arg(tue_23_30.to_string())
        .output()
        .expect("eval overnight");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let j: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(j["evaluation"]["active_rate"], "10Gbps");
}
