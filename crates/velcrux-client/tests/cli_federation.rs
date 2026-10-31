//! Integration tests for Option CJ: Cross-Region Multi-Cloud Distributed Storage
//! Federation & Active-Active Geo-Replication (`ADR-052`).

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_federation_status_human() {
    let output = Command::new(velcrux_bin())
        .arg("federation")
        .arg("status")
        .output()
        .expect("execute velcrux federation status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Cross-Region Multi-Cloud Distributed Storage Federation Status"));
    assert!(stdout.contains("Status:                 operational"));
    assert!(stdout.contains("Routing Policy:         active_active (ActiveActive)"));
    assert!(stdout.contains("Active Providers:       4"));
    assert!(stdout.contains("aws-us-east-1"));
    assert!(stdout.contains("gcp-europe-west3"));
    assert!(stdout.contains("azure-eastus"));
    assert!(stdout.contains("minio-edge"));
    assert!(stdout.contains("Telemetry Counters:"));
    assert!(stdout.contains("Operations Total:"));
    assert!(stdout.contains("Cache Hits:"));
}

#[test]
fn test_cli_federation_status_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("federation")
        .arg("status")
        .output()
        .expect("execute velcrux --json federation status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("valid JSON expected from --json federation status");

    assert_eq!(json_val["status"], "operational");
    assert_eq!(json_val["active_providers"], 4);
    assert!(json_val["routing_policy"]
        .as_str()
        .unwrap()
        .contains("ActiveActive"));
    assert!(json_val["providers"].is_array());
    assert_eq!(json_val["providers"].as_array().unwrap().len(), 4);
    assert!(json_val["operations_total"].is_number());
}

#[test]
fn test_cli_federation_put_and_get_roundtrip() {
    let dir = tempdir().expect("create temp dir");
    let input_file = dir.path().join("model.bin");
    let output_file = dir.path().join("model_restored.bin");

    let test_data = b"Multi-Cloud Active-Active Federated Storage Test Payload across AWS, GCS, Azure, and MinIO!";
    fs::write(&input_file, test_data).expect("write model.bin");

    // 1. Put object into federated namespace
    let put_output = Command::new(velcrux_bin())
        .arg("federation")
        .arg("put")
        .arg("--input")
        .arg(&input_file)
        .arg("--object-key")
        .arg("models/v1/weights.bin")
        .output()
        .expect("execute federation put");

    assert!(
        put_output.status.success(),
        "put failed: {:?}",
        String::from_utf8_lossy(&put_output.stderr)
    );
    let put_stdout = String::from_utf8_lossy(&put_output.stdout);
    assert!(put_stdout.contains("Multi-Cloud Active-Active Put Completed"));
    assert!(put_stdout.contains("models/v1/weights.bin"));
    assert!(put_stdout.contains("Replicated Providers:   4"));

    // 2. Read object back through multi-cloud read-through cache
    let get_output = Command::new(velcrux_bin())
        .arg("federation")
        .arg("get")
        .arg("--object-key")
        .arg("models/v1/weights.bin")
        .arg("--output")
        .arg(&output_file)
        .output()
        .expect("execute federation get");

    assert!(
        get_output.status.success(),
        "get failed: {:?}",
        String::from_utf8_lossy(&get_output.stderr)
    );
    let get_stdout = String::from_utf8_lossy(&get_output.stdout);
    assert!(get_stdout.contains("Multi-Cloud Federated Get Completed"));
    assert!(get_stdout.contains("models/v1/weights.bin"));

    let restored_data = fs::read(&output_file).expect("read restored file");
    assert_eq!(restored_data, test_data);
}

#[test]
fn test_cli_federation_sync() {
    let output = Command::new(velcrux_bin())
        .arg("federation")
        .arg("sync")
        .arg("--policy")
        .arg("causal")
        .output()
        .expect("execute federation sync");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Multi-Cloud Cross-Region Sync Report"));
    assert!(stdout.contains("Objects Scanned:"));
    assert!(stdout.contains("Objects Synced:"));
    assert!(stdout.contains("Conflicts Detected:"));
    assert!(stdout.contains("Conflicts Resolved:"));

    let json_output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("federation")
        .arg("sync")
        .arg("--policy")
        .arg("lww")
        .output()
        .expect("execute federation sync json");

    assert!(json_output.status.success());
    let val: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert!(val["objects_scanned"].is_number());
    assert!(val["conflicts_detected"].is_number());
}

#[test]
fn test_cli_federation_providers_list() {
    let output = Command::new(velcrux_bin())
        .arg("federation")
        .arg("providers")
        .output()
        .expect("execute federation providers");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Registered Federated Cloud Providers"));
    assert!(stdout.contains("aws-us-east-1"));
    assert!(stdout.contains("gcp-europe-west3"));
    assert!(stdout.contains("azure-eastus"));
    assert!(stdout.contains("minio-edge"));

    let json_out = Command::new(velcrux_bin())
        .arg("--json")
        .arg("federation")
        .arg("providers")
        .output()
        .expect("execute federation providers json");

    assert!(json_out.status.success());
    let val: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(val["providers"].as_array().unwrap().len(), 4);
}

#[test]
fn test_cli_federation_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("federation")
        .arg("benchmark")
        .arg("--size")
        .arg("1024")
        .arg("--iterations")
        .arg("10")
        .output()
        .expect("execute federation benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Multi-Cloud Federation Benchmark"));
    assert!(stdout.contains("Active-Active Put:"));
    assert!(stdout.contains("Read Cache Hit:"));
    assert!(stdout.contains("Multi-Cloud Fetch:"));
    assert!(stdout.contains("Conflict Resolution:"));
    assert!(stdout.contains("Failover Switch:"));

    let json_output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("federation")
        .arg("benchmark")
        .arg("--size")
        .arg("512")
        .arg("--iterations")
        .arg("5")
        .output()
        .expect("execute federation benchmark json");

    assert!(json_output.status.success());
    let val: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(val["iterations"], 5);
    assert_eq!(val["payload_size_bytes"], 512);
    assert!(val["put_throughput_bytes_per_sec"].as_f64().unwrap() > 0.0);
    assert!(val["cache_hit_throughput_bytes_per_sec"].as_f64().unwrap() > 0.0);
    assert!(val["conflict_resolution_ops_per_sec"].as_f64().unwrap() > 0.0);
}
