//! Integration tests for Kubernetes Operator & Declarative CRDs (Option CU / ADR-063).

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn get_bin_path() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("failed to get test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("velcrux");
    path
}

fn get_example_manifest() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&manifest_dir);
    root.join("packaging/k8s/examples/transfer-dataset.yaml")
}

#[test]
fn test_cli_k8s_crd_cluster() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["k8s", "crd", "--kind", "cluster"])
        .output()
        .expect("failed to run velcrux k8s crd");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("kind: CustomResourceDefinition"));
    assert!(stdout.contains("name: velcruxclusters.velcrux.io"));
    assert!(stdout.contains("storageBackend"));
    assert!(stdout.contains("quicPort"));
}

#[test]
fn test_cli_k8s_crd_transfer() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["k8s", "crd", "--kind", "transfer"])
        .output()
        .expect("failed to run velcrux k8s crd");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("kind: CustomResourceDefinition"));
    assert!(stdout.contains("name: velcruxtransfers.velcrux.io"));
    assert!(stdout.contains("sourceUrl"));
    assert!(stdout.contains("destinationPath"));
    assert!(stdout.contains("bdpTuning"));
}

#[test]
fn test_cli_k8s_crd_file_output() {
    let temp_dir = tempdir().unwrap();
    let dest_file = temp_dir.path().join("crds/all.yaml");

    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["k8s", "crd", "--output", dest_file.to_str().unwrap()])
        .output()
        .expect("failed to run velcrux k8s crd");

    assert!(output.status.success());
    assert!(dest_file.exists());
    let content = fs::read_to_string(&dest_file).unwrap();
    assert!(content.contains("name: velcruxclusters.velcrux.io"));
    assert!(content.contains("name: velcruxtransfers.velcrux.io"));
}

#[test]
fn test_cli_k8s_operator_manifest() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args([
            "k8s",
            "operator-manifest",
            "--image",
            "ghcr.io/velcrux/operator:v0.1.0",
            "--namespace",
            "velcrux-infra",
        ])
        .output()
        .expect("failed to run velcrux k8s operator-manifest");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("kind: ServiceAccount"));
    assert!(stdout.contains("name: velcrux-operator"));
    assert!(stdout.contains("namespace: velcrux-infra"));
    assert!(stdout.contains("kind: ClusterRole"));
    assert!(stdout.contains("kind: Deployment"));
    assert!(stdout.contains("image: ghcr.io/velcrux/operator:v0.1.0"));
}

#[test]
fn test_cli_k8s_validate_valid_yaml() {
    let bin = get_bin_path();
    let manifest_path = get_example_manifest();
    let output = Command::new(&bin)
        .args([
            "k8s",
            "validate",
            "--file",
            manifest_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("failed to run velcrux k8s validate");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["name"], "nightly-ai-weights-sync");
    assert_eq!(parsed["namespace"], "default");
}

#[test]
fn test_cli_k8s_validate_invalid_spec() {
    let temp_dir = tempdir().unwrap();
    let bad_manifest = temp_dir.path().join("bad.yaml");
    fs::write(
        &bad_manifest,
        r#"apiVersion: velcrux.io/v1alpha1
kind: VelcruxTransfer
metadata:
  name: bad-transfer
spec:
  sourceUrl: "http://insecure-http/data"
  destinationPath: "/mnt/data"
"#,
    )
    .unwrap();

    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["k8s", "validate", "--file", bad_manifest.to_str().unwrap(), "--json"])
        .output()
        .expect("failed to run velcrux k8s validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["valid"], false);
    assert!(parsed["error"].as_str().unwrap().contains("must use velcrux://"));
}

#[test]
fn test_cli_k8s_reconcile_full_cycle() {
    let bin = get_bin_path();
    let manifest_path = get_example_manifest();
    let output = Command::new(&bin)
        .args([
            "k8s",
            "reconcile",
            "--file",
            manifest_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("failed to run velcrux k8s reconcile");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Since schedule is present, it transitions to Scheduled
    assert_eq!(parsed["updatedStatus"]["phase"], "Scheduled");
    assert_eq!(parsed["events"][0]["reason"], "TransferScheduled");
}

#[test]
fn test_cli_k8s_reconcile_failure_and_retry() {
    let bin = get_bin_path();
    let manifest_path = get_example_manifest();
    let output = Command::new(&bin)
        .args([
            "k8s",
            "reconcile",
            "--file",
            manifest_path.to_str().unwrap(),
            "--simulate-failure",
            "QUIC loss timeout",
            "--json",
        ])
        .output()
        .expect("failed to run velcrux k8s reconcile");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["updatedStatus"]["phase"], "Retrying");
    assert_eq!(parsed["updatedStatus"]["retryCount"], 1);
    assert_eq!(parsed["events"][0]["reason"], "TransferTransientFailure");
    assert!(parsed["requeueAfterSecs"].as_u64().unwrap() >= 5);
}
