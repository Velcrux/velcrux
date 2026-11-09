//! Integration tests for Option DE: Quantum Key Distribution (QKD) Optical Fiber & Satellite Entanglement Key Exchange (`ADR-073`).

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
fn test_cli_qkd_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("status")
        .output()
        .expect("execute qkd status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("QUANTUM KEY DISTRIBUTION (QKD) OPTICAL & SATELLITE ENGINE STATUS"));
    assert!(stdout.contains("Physical Optical Fiber Link"));
    assert!(stdout.contains("LEO Satellite Quantum Optical Downlink"));
    assert!(stdout.contains("ETSI GS QKD 014 Key Store Buffer"));
    assert!(stdout.contains("Shor-Preskill QBER"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute qkd status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse qkd status json");
    assert!(
        val["optical_fiber"]["attenuation_db_per_km"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    assert!(
        val["satellite_downlink"]["orbit_altitude_km"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    assert!(
        val["safety_thresholds"]["bell_chsh_tsirelson_bound"]
            .as_f64()
            .unwrap()
            > 2.0
    );
}

#[test]
fn test_cli_qkd_exchange_bb84_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("exchange")
        .arg("--protocol")
        .arg("bb84")
        .arg("--channel")
        .arg("fiber")
        .arg("--pulses")
        .arg("10000")
        .output()
        .expect("execute qkd exchange bb84");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BB84 DECOY-STATE OPTICAL QKD EXCHANGE SESSION REPORT"));
    assert!(stdout.contains("Optical Channel Loss:"));
    assert!(stdout.contains("Measured QBER:"));
    assert!(stdout.contains("Final Extracted Key:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("exchange")
        .arg("--protocol")
        .arg("bb84")
        .arg("--pulses")
        .arg("10000")
        .arg("--json")
        .output()
        .expect("execute qkd exchange bb84 json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse qkd exchange bb84 json");
    assert!(val["protocol"].as_str().unwrap().contains("BB84"));
    assert!(val["is_secure"].as_bool().unwrap());
    assert_eq!(val["final_key_hex"].as_str().unwrap().len(), 64);
}

#[test]
fn test_cli_qkd_exchange_e91_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("exchange")
        .arg("--protocol")
        .arg("e91")
        .arg("--channel")
        .arg("fiber")
        .arg("--pulses")
        .arg("10000")
        .output()
        .expect("execute qkd exchange e91");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("E91 ENTANGLED PHOTON QKD EXCHANGE SESSION REPORT"));
    assert!(stdout.contains("CHSH Bell Parameter S:"));
    assert!(stdout.contains("Bell Inequality Viol:"));
    assert!(stdout.contains("YES (Quantum Nature Proven)"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("exchange")
        .arg("--protocol")
        .arg("e91")
        .arg("--pulses")
        .arg("10000")
        .arg("--json")
        .output()
        .expect("execute qkd exchange e91 json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse qkd exchange e91 json");
    assert!(val["bell_inequality_violated"].as_bool().unwrap());
    assert!(val["chsh_s_value"].as_f64().unwrap() > 2.0);
    assert!(!val["final_key_hex"].as_str().unwrap().is_empty());
    assert!(val["sifted_key_bits"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_qkd_keys_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("keys")
        .output()
        .expect("execute qkd keys");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ETSI GS QKD 014 STORED QUANTUM KEYS BUFFER"));
    assert!(stdout.contains("KEY ID (UUID)"));
    assert!(stdout.contains("PROTOCOL"));
    assert!(stdout.contains("STATUS"));
    assert!(stdout.contains("Total Listed Keys:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("keys")
        .arg("--json")
        .output()
        .expect("execute qkd keys json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse qkd keys json");
    let arr = val.as_array().expect("array of keys");
    assert_eq!(arr.len(), 3);
}

#[test]
fn test_cli_qkd_replenish_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("replenish")
        .arg("--count")
        .arg("2")
        .arg("--peer")
        .arg("sae-peer-us-east")
        .output()
        .expect("execute qkd replenish");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ETSI GS QKD 014 AUTOMATED KEY REPLENISHMENT REPORT"));
    assert!(stdout.contains("Target Keys Requested:  2"));
    assert!(stdout.contains("Quantum Keys Generated: 2"));
    assert!(stdout.contains("Hybrid PQC KDF Binding:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("qkd")
        .arg("replenish")
        .arg("--count")
        .arg("2")
        .arg("--json")
        .output()
        .expect("execute qkd replenish json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse qkd replenish json");
    assert_eq!(val["keys_requested"].as_u64().unwrap(), 2);
    assert_eq!(val["keys_generated"].as_u64().unwrap(), 2);
    assert!(val["hybrid_pqc_key_preview"].as_str().unwrap().len() > 0);
}
