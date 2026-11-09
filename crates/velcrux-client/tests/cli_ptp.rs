//! Integration tests for Option DG: Hardware PTP (IEEE 1588v2) Nanosecond High-Precision Clock Synchronization & Bounded Transfer Ordering Mesh (`ADR-075`).

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
fn test_cli_ptp_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("ptp")
        .arg("status")
        .output()
        .expect("execute ptp status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("IEEE 1588v2 PRECISION TIME PROTOCOL (PTP) HARDWARE STATUS"));
    assert!(stdout.contains("ORDINARY_CLOCK_SLAVE"));
    assert!(stdout.contains("SLAVE (Locked to Grandmaster)"));
    assert!(stdout.contains("Offset from Master:"));
    assert!(stdout.contains("Mean One-Way Delay:"));
    assert!(stdout.contains("Servo Lock Status:"));
    assert!(stdout.contains("Jitter RMS:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("ptp")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute ptp status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse ptp status json");
    assert_eq!(val["clock_role"].as_str().unwrap(), "ORDINARY_CLOCK_SLAVE");
    assert_eq!(val["port_state"].as_str().unwrap(), "SLAVE");
    assert_eq!(val["domain_number"].as_u64().unwrap(), 0);
    assert!(val["local_clock_identity"].as_str().unwrap().len() >= 16);
    assert!(val["grandmaster_identity"].as_str().unwrap().len() >= 16);
    assert_eq!(val["steps_removed"].as_u64().unwrap(), 1);
    assert_eq!(val["phase_lock_threshold_nanos"].as_i64().unwrap(), 50);
}

#[test]
fn test_cli_ptp_peers_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("ptp")
        .arg("peers")
        .output()
        .expect("execute ptp peers");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMCA FOREIGN GRANDMASTER CANDIDATES & DATASET COMPARISONS"));
    assert!(stdout.contains("CLOCK IDENTITY"));
    assert!(stdout.contains("ELECTED GM"));
    assert!(stdout.contains("CANDIDATE"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("ptp")
        .arg("peers")
        .arg("--json")
        .output()
        .expect("execute ptp peers json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse ptp peers json");
    let arr = val.as_array().expect("array of peers");
    assert_eq!(arr.len(), 2);

    let elected = arr
        .iter()
        .find(|p| p["is_selected_grandmaster"].as_bool().unwrap())
        .expect("must have elected grandmaster");
    assert_eq!(elected["clock_class"].as_u64().unwrap(), 6); // GNSS primary atomic clock
    assert_eq!(elected["steps_removed"].as_u64().unwrap(), 0);
}

#[test]
fn test_cli_ptp_sync_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("ptp")
        .arg("sync")
        .arg("--iterations")
        .arg("10")
        .arg("--domain")
        .arg("2")
        .output()
        .expect("execute ptp sync");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PTP 4-TIMESTAMP EXCHANGE SYNCHRONIZATION SESSION REPORT"));
    assert!(stdout.contains("PTP Domain:             2"));
    assert!(stdout.contains("Iterations Executed:    10"));
    assert!(stdout.contains("Final Clock Offset:"));
    assert!(stdout.contains("Mean Path Delay:"));
    assert!(stdout.contains("Locked: true"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("ptp")
        .arg("sync")
        .arg("--iterations")
        .arg("8")
        .arg("--json")
        .output()
        .expect("execute ptp sync json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse ptp sync json");
    assert_eq!(val["domain_number"].as_u64().unwrap(), 0);
    assert_eq!(val["iterations_completed"].as_u64().unwrap(), 8);
    assert_eq!(val["is_phase_locked"].as_bool().unwrap(), true);
    assert_eq!(val["lock_status"].as_str().unwrap(), "LOCKED_PHASE");
}

#[test]
fn test_cli_ptp_ordering_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("ptp")
        .arg("ordering")
        .arg("--transfer-id")
        .arg("transfer-eu-central-001")
        .arg("--jitter")
        .arg("150")
        .output()
        .expect("execute ptp ordering");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BOUNDED-SKEW CAUSAL TRANSFER ORDERING & TRUETIME COMMIT REPORT"));
    assert!(stdout.contains("transfer-eu-central-001"));
    assert!(stdout.contains("Originating Region:     us-east-dc1"));
    assert!(stdout.contains("Clock Uncertainty (±ε):"));
    assert!(stdout.contains("Required Commit Wait:"));
    assert!(stdout.contains("Safe Release Time:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("ptp")
        .arg("ordering")
        .arg("--transfer-id")
        .arg("transfer-eu-central-001")
        .arg("--jitter")
        .arg("150")
        .arg("--json")
        .output()
        .expect("execute ptp ordering json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse ptp ordering json");
    assert_eq!(
        val["transfer_id"].as_str().unwrap(),
        "transfer-eu-central-001"
    );
    assert_eq!(val["region_id"].as_str().unwrap(), "us-east-dc1");
    let epsilon = val["uncertainty_epsilon_nanos"].as_u64().unwrap();
    let wait = val["required_commit_wait_nanos"].as_u64().unwrap();
    let earliest = val["earliest_bound_nanos"].as_u64().unwrap();
    let latest = val["latest_bound_nanos"].as_u64().unwrap();
    assert_eq!(wait, 2 * epsilon);
    assert_eq!(latest - earliest, 2 * epsilon);
}
