//! Integration tests for pluggable webhook event notification and audit bus CLI (Option BB).

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
fn test_cli_webhook_list_table() {
    let output = Command::new(velcrux_bin())
        .arg("webhook")
        .arg("list")
        .output()
        .expect("execute velcrux webhook list");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("PLUGGABLE WEBHOOK EVENT NOTIFICATIONS & AUDIT BUS"));
    assert!(stdout.contains("Total Published"));
    assert!(stdout.contains("Deliveries Succeeded"));
    assert!(stdout.contains("Dead-Lettered (DLQ)"));
    assert!(stdout.contains("sub-audit-sink"));
    assert!(stdout.contains("sub-ops-pager"));
    assert!(stdout.contains("https://audit.internal.corp/events"));
    assert!(stdout.contains("https://pager.ops.corp/v1/alerts"));
}

#[test]
fn test_cli_webhook_list_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("webhook")
        .arg("list")
        .output()
        .expect("execute velcrux --json webhook list");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json webhook list");

    assert_eq!(json_val["event"], "webhook_list");
    assert!(json_val["subscriptions"].is_array());
    assert_eq!(json_val["subscriptions"].as_array().unwrap().len(), 2);
    assert!(json_val["metrics"].is_object());
    assert_eq!(json_val["dlq_size"], 0);
}

#[test]
fn test_cli_webhook_test_table() {
    let output = Command::new(velcrux_bin())
        .arg("webhook")
        .arg("test")
        .arg("https://api.pagerduty.com/v2/events")
        .arg("--secret")
        .arg("super-secret-hmac-token-42")
        .arg("--event")
        .arg("chunk.corrupted")
        .output()
        .expect("execute velcrux webhook test");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("WEBHOOK TEST NOTIFICATION DISPATCHED"));
    assert!(stdout.contains("Target Endpoint      : https://api.pagerduty.com/v2/events"));
    assert!(stdout.contains("Event Type           : chunk.corrupted"));
    assert!(stdout.contains("Signature (X-Velcrux): t="));
    assert!(stdout.contains("HMAC Validation      : PASS (256-bit constant-time verified)"));
    assert!(stdout.contains("Delivery Status      : HTTP 200 OK (verified)"));
}

#[test]
fn test_cli_webhook_test_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("webhook")
        .arg("test")
        .arg("https://api.datadoghq.com/v1/events")
        .arg("--secret")
        .arg("dd-secret-token-77")
        .arg("--event")
        .arg("audit.action")
        .output()
        .expect("execute velcrux --json webhook test");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json webhook test");

    assert_eq!(json_val["event"], "webhook_test_dispatched");
    assert_eq!(json_val["url"], "https://api.datadoghq.com/v1/events");
    assert_eq!(json_val["event_type"], "audit.action");
    assert_eq!(json_val["verified"], true);
    assert!(json_val["signature"].as_str().unwrap().starts_with("t="));
    assert_eq!(json_val["status"], "delivered_mock_ok");
}

#[test]
fn test_cli_webhook_dlq_operations() {
    // 1. Text table DLQ inspection
    let output = Command::new(velcrux_bin())
        .arg("webhook")
        .arg("dlq")
        .output()
        .expect("execute velcrux webhook dlq");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("WEBHOOK DEAD-LETTER QUEUE (DLQ)"));
    assert!(stdout.contains("Initial DLQ Entries  : 0"));
    assert!(stdout.contains("Queue Drained        : No"));

    // 2. JSON DLQ drain
    let output_drain = Command::new(velcrux_bin())
        .arg("--json")
        .arg("webhook")
        .arg("dlq")
        .arg("--drain")
        .output()
        .expect("execute velcrux --json webhook dlq --drain");

    assert!(output_drain.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output_drain.stderr));
    let json_val: serde_json::Value =
        serde_json::from_slice(&output_drain.stdout).expect("valid JSON expected from --json webhook dlq --drain");

    assert_eq!(json_val["event"], "webhook_dlq");
    assert_eq!(json_val["drained"], true);
    assert_eq!(json_val["current_entries"], 0);
}
