//! Integration tests for multipath transport bonding CLI (`REQUIREMENTS.md` §74, §75).

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
fn test_cli_multipath_status_table() {
    let output = Command::new(velcrux_bin())
        .arg("multipath")
        .arg("--multipath-scheduler")
        .arg("weighted")
        .output()
        .expect("execute velcrux multipath");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("VELCRUX MULTI-PATH TRANSPORT AGGREGATION STATUS"));
    assert!(stdout.contains("Scheduler Policy     : weighted_bandwidth"));
    assert!(stdout.contains("Total Subflow Paths"));
    assert!(stdout.contains("PATH ID"));
    assert!(stdout.contains("INTERFACE"));
    assert!(stdout.contains("STATE"));
}

#[test]
fn test_cli_multipath_json_output() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("multipath")
        .arg("--multipath-scheduler")
        .arg("min-rtt")
        .output()
        .expect("execute velcrux --json multipath");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json multipath");

    assert_eq!(json_val["policy"], "lowest_latency_first");
    assert!(json_val["total_paths"].as_u64().unwrap() >= 1);
    assert!(json_val["paths"].is_array());
}

#[test]
fn test_cli_multipath_policies_validation() {
    for policy in &["round-robin", "redundant", "failover"] {
        let output = Command::new(velcrux_bin())
            .arg("multipath")
            .arg("--multipath-scheduler")
            .arg(policy)
            .output()
            .expect("execute velcrux multipath");

        assert!(output.status.success());
    }
}
