//! Integration tests for Forward Error Correction (FEC) CLI (Option BH, `REQUIREMENTS.md` §13, §47, §88).

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
fn test_cli_fec_status_human() {
    let output = Command::new(velcrux_bin())
        .arg("fec")
        .arg("status")
        .output()
        .expect("execute velcrux fec status");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("FORWARD ERROR CORRECTION (FEC) OPERATIONAL STATUS"));
    assert!(stdout.contains("Erasure Field        : GF(2^8) (Primitive Polynomial: 0x11d)"));
    assert!(stdout.contains("Generator Matrix     : Cauchy Generator Matrix (MDS Guaranteed)"));
    assert!(stdout.contains("Dynamic Loss Tiers (Adaptive Rate Scaling):"));
    assert!(stdout.contains("K=20, M=0"));
    assert!(stdout.contains("K=8,  M=2"));
}

#[test]
fn test_cli_fec_status_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("fec")
        .arg("status")
        .arg("--profile")
        .arg("satellite")
        .output()
        .expect("execute velcrux --json fec status");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json fec status");

    assert_eq!(json_val["event"], "fec_status");
    assert_eq!(json_val["status"]["profile"], "satellite");
    assert_eq!(json_val["status"]["active_k"], 8);
    assert_eq!(json_val["status"]["active_m"], 2);
    assert_eq!(json_val["status"]["field"], "GF(2^8)");
    assert_eq!(json_val["status"]["mds_guaranteed"], true);
    assert!(json_val["status"]["loss_tiers"].is_array());
}

#[test]
fn test_cli_fec_test_simulation_human() {
    let output = Command::new(velcrux_bin())
        .arg("fec")
        .arg("test")
        .arg("--profile")
        .arg("satellite")
        .arg("--loss-rate")
        .arg("0.05")
        .arg("--payload-size")
        .arg("65536")
        .output()
        .expect("execute velcrux fec test");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("FEC ERASURE CODING RECOVERY SIMULATION"));
    assert!(stdout.contains("Coding Rate (K+M, K) : (8 + 2, 8)"));
    assert!(stdout.contains("Simulated Loss Rate  : 5.00%"));
    assert!(stdout.contains("Recovery Success Rate: 100.00%"));
    assert!(stdout.contains("PASSED — ZERO ARQ RETRANSMISSION STALLS"));
}

#[test]
fn test_cli_fec_test_simulation_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("fec")
        .arg("test")
        .arg("--profile")
        .arg("medium")
        .arg("--loss-rate")
        .arg("0.03")
        .arg("--payload-size")
        .arg("32768")
        .output()
        .expect("execute velcrux --json fec test");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json fec test");

    assert_eq!(json_val["event"], "fec_simulation_completed");
    assert_eq!(json_val["report"]["k"], 16);
    assert_eq!(json_val["report"]["m"], 2);
    assert_eq!(json_val["report"]["unrecoverable_blocks"], 0);
    assert_eq!(json_val["report"]["successful_recovery_pct"], 100.0);
}

#[test]
fn test_cli_fec_global_flag_help() {
    let output = Command::new(velcrux_bin())
        .arg("--help")
        .output()
        .expect("execute velcrux --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--fec <FEC>"));
    assert!(stdout.contains("Forward Error Correction"));
}
