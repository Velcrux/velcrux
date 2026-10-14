//! Integration tests for cross-cluster WAN geo-replication CLI (Option BA).

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
fn test_cli_geo_status_table() {
    let output = Command::new(velcrux_bin())
        .arg("geo")
        .arg("status")
        .output()
        .expect("execute velcrux geo status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("VELCRUX CROSS-CLUSTER WAN GEO-REPLICATION STATUS"));
    assert!(stdout.contains("Local Region         : us-east-1"));
    assert!(stdout.contains("Conflict Policy      : Last-Write-Wins (LWW)"));
    assert!(stdout.contains("Total Remote Regions : 2"));
    assert!(stdout.contains("REGION ID"));
    assert!(stdout.contains("eu-central-1"));
    assert!(stdout.contains("ap-tokyo-1"));
}

#[test]
fn test_cli_geo_status_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("geo")
        .arg("status")
        .output()
        .expect("execute velcrux --json geo status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json geo status");

    assert_eq!(json_val["local_region"], "us-east-1");
    assert_eq!(json_val["conflict_policy"], "Last-Write-Wins (LWW)");
    assert_eq!(json_val["total_regions"], 2);
    assert_eq!(json_val["active_regions"], 2);
    assert!(json_val["regions"].is_array());
    assert_eq!(json_val["regions"].as_array().unwrap().len(), 2);
}

#[test]
fn test_cli_geo_status_custom_regions_and_policy() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("geo")
        .arg("status")
        .arg("--local-region")
        .arg("ap-tokyo-1")
        .arg("--regions")
        .arg("eu-west-1=10.1.0.1:7443,us-east-1=10.2.0.1:7443")
        .arg("--conflict-policy")
        .arg("primary")
        .arg("--primary-region")
        .arg("us-east-1")
        .output()
        .expect("execute velcrux geo status custom");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected");

    assert_eq!(json_val["local_region"], "ap-tokyo-1");
    assert_eq!(json_val["conflict_policy"], "Primary-Authority (us-east-1)");
    assert_eq!(json_val["total_regions"], 2);
}

#[test]
fn test_cli_geo_sync_table() {
    let output = Command::new(velcrux_bin())
        .arg("geo")
        .arg("sync")
        .arg("--source-region")
        .arg("us-east-1")
        .arg("--target-region")
        .arg("eu-central-1")
        .output()
        .expect("execute velcrux geo sync");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CROSS-CLUSTER WAN GEO-REPLICATION SYNCHRONIZED"));
    assert!(stdout.contains("Source Region        : us-east-1"));
    assert!(stdout.contains("Target Region        : eu-central-1"));
    assert!(stdout.contains("Replication State    : Synchronized (Vector Clocks Balanced)"));
}

#[test]
fn test_cli_geo_sync_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("geo")
        .arg("sync")
        .arg("--source-region")
        .arg("us-east-1")
        .arg("--target-region")
        .arg("eu-central-1")
        .output()
        .expect("execute velcrux --json geo sync");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json geo sync");

    assert_eq!(json_val["event"], "geo_sync_completed");
    assert_eq!(json_val["source_region"], "us-east-1");
    assert_eq!(json_val["target_region"], "eu-central-1");
    assert_eq!(json_val["status"], "synchronized");
}
