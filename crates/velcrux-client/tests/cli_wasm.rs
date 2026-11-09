//! Integration tests for Option DF: Confidential Multi-Tenant eBPF Sandboxed Streaming Compute & In-Flight WASM Payload Transformation (`ADR-074`).

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
fn test_cli_wasm_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("status")
        .output()
        .expect("execute wasm status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CONFIDENTIAL EBPF & IN-FLIGHT WASI 0.2 STREAMING COMPUTE STATUS"));
    assert!(stdout.contains("Runtime Engine:"));
    assert!(stdout.contains("WASI 0.2 (Preview 2 Component Model)"));
    assert!(stdout.contains("WASM Page Size:         65536 bytes (64 KiB)"));
    assert!(stdout.contains("eBPF Fast-Path Stream Classifier"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute wasm status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse wasm status json");
    assert_eq!(
        val["linear_memory_page_size_bytes"].as_u64().unwrap(),
        65536
    );
    assert!(val["ebpf_fastpath_classifier"]["enabled"]
        .as_bool()
        .unwrap());
    assert!(val["active_tenants_count"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_wasm_inspect_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("inspect")
        .arg("--module")
        .arg("pii_redactor")
        .output()
        .expect("execute wasm inspect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("WASM MODULE INSPECTION & CAPABILITY AUDIT"));
    assert!(stdout.contains("Module Identifier:      pii_redactor"));
    assert!(stdout.contains("Binary Magic Header:    0x00 0x61 0x73 0x6D (\\0asm)"));
    assert!(stdout.contains("velcrux_transform_chunk"));
    assert!(stdout.contains("wasi:random/random:       GRANTED"));
    assert!(stdout.contains("Host Filesystem Access:   BLOCKED (Confidential Sandbox)"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("inspect")
        .arg("--module")
        .arg("pii_redactor")
        .arg("--json")
        .output()
        .expect("execute wasm inspect json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse wasm inspect json");
    assert_eq!(val["module_name"].as_str().unwrap(), "pii_redactor");
    assert_eq!(val["binary_version"].as_u64().unwrap(), 1);
    assert!(val["wasi_capabilities"]["disallow_filesystem"]
        .as_bool()
        .unwrap());
}

#[test]
fn test_cli_wasm_pipeline_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("pipeline")
        .arg("--tenant")
        .arg("tenant-finance")
        .output()
        .expect("execute wasm pipeline");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("REGISTERED STREAMING IN-FLIGHT TRANSFORMATION PIPELINES"));
    assert!(stdout.contains("Tenant ID: tenant-finance"));
    assert!(stdout.contains("pipeline-pii-redact [ACTIVE]"));
    assert!(stdout.contains("pipeline-schema-pack [ACTIVE]"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("pipeline")
        .arg("--tenant")
        .arg("tenant-finance")
        .arg("--json")
        .output()
        .expect("execute wasm pipeline json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse wasm pipeline json");
    let arr = val.as_array().expect("array of pipelines");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["tenant_id"].as_str().unwrap(), "tenant-finance");
}

#[test]
fn test_cli_wasm_execute_pii_text_and_json() {
    let sensitive_input =
        "Client record: John Doe, Visa 4111-2222-3333-4444, SSN 123-45-6789 verified.";

    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("execute")
        .arg("--pipeline")
        .arg("pipeline-pii-redact")
        .arg("--input")
        .arg(sensitive_input)
        .output()
        .expect("execute wasm execute");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("IN-FLIGHT STREAMING WASM TRANSFORMATION REPORT"));
    assert!(stdout.contains("Pipeline ID:            pipeline-pii-redact"));
    assert!(stdout.contains("Status:                 SUCCESS"));
    assert!(stdout.contains("Transformed Output Preview:"));
    assert!(stdout.contains("XXXX-XXXX-XXXX-XXXX"));
    assert!(stdout.contains("XXX-XX-XXXX"));
    assert!(!stdout.contains("4111-2222-3333-4444"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("execute")
        .arg("--pipeline")
        .arg("pipeline-pii-redact")
        .arg("--input")
        .arg(sensitive_input)
        .arg("--json")
        .output()
        .expect("execute wasm execute json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse wasm execute json");
    assert!(val["is_success"].as_bool().unwrap());
    assert!(val["total_gas_consumed"].as_u64().unwrap() > 0);
    assert!(val["output_preview"]
        .as_str()
        .unwrap()
        .contains("XXXX-XXXX-XXXX-XXXX"));
}

#[test]
fn test_cli_wasm_execute_schema_text_and_json() {
    let json_input = "{\"user\":\"charlie\",\"card\":\"5555-4444-3333-2222\",\"amount\":1500}";

    let output = Command::new(velcrux_bin())
        .arg("wasm")
        .arg("execute")
        .arg("--pipeline")
        .arg("pipeline-schema-pack")
        .arg("--input")
        .arg(json_input)
        .output()
        .expect("execute wasm execute schema");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("IN-FLIGHT STREAMING WASM TRANSFORMATION REPORT"));
    assert!(stdout.contains("Pipeline ID:            pipeline-schema-pack"));
    assert!(stdout.contains("Stages Executed:        3"));
    assert!(stdout.contains("SUCCESS"));
}
