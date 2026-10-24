//! Integration tests for Option BX: Automated Continuous Chaos Engineering,
//! WAN Impairment & Network Fault Injection Suite (`ADR-040`).

#![forbid(unsafe_code)]

use std::process::Command;
use velcrux_core::chaos::{
    ChaosConfig, ChaosEngine, ChaosOutcome, ChaosPrng, GilbertElliottConfig, GilbertElliottModel,
};
use velcrux_core::util::Hash;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_chaos_status_text_and_json() {
    // 1. Text format
    let output = Command::new(velcrux_bin())
        .arg("chaos")
        .arg("status")
        .output()
        .expect("execute chaos status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Velcrux Chaos Fault Injection Status ==="));
    assert!(stdout.contains("Engine Status:"));
    assert!(stdout.contains("Packets Processed:"));
    assert!(stdout.contains("Packets Dropped:"));

    // 2. JSON format
    let output_json = Command::new(velcrux_bin())
        .arg("chaos")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute chaos status --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON status report");
    assert!(parsed.get("enabled").is_some());
    assert!(parsed.get("active_profile").is_some());
    assert_eq!(
        parsed.get("blackhole_active").and_then(|v| v.as_bool()),
        Some(false)
    );
}

#[test]
fn test_cli_chaos_profile_list_and_single() {
    // 1. List all profiles (text)
    let output_all = Command::new(velcrux_bin())
        .arg("chaos")
        .arg("profile")
        .output()
        .expect("execute chaos profile");

    assert!(output_all.status.success());
    let stdout = String::from_utf8_lossy(&output_all.stdout);
    assert!(stdout.contains("=== Preconfigured WAN Impairment Profiles ==="));
    assert!(stdout.contains("Profile: subsea"));
    assert!(stdout.contains("Profile: satellite"));
    assert!(stdout.contains("Profile: cellular"));
    assert!(stdout.contains("Profile: byzantine"));

    // 2. Specific profile (JSON)
    let output_single = Command::new(velcrux_bin())
        .arg("chaos")
        .arg("profile")
        .arg("subsea")
        .arg("--json")
        .output()
        .expect("execute chaos profile subsea --json");

    assert!(output_single.status.success());
    let parsed: Vec<serde_json::Value> =
        serde_json::from_slice(&output_single.stdout).expect("valid JSON profile info");
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0].get("name").and_then(|v| v.as_str()),
        Some("subsea")
    );
    assert!(parsed[0].get("delay_ms").and_then(|v| v.as_u64()).unwrap() > 0);
}

#[test]
fn test_cli_chaos_benchmark_simulation() {
    // 1. Text benchmark output
    let output = Command::new(velcrux_bin())
        .arg("chaos")
        .arg("benchmark")
        .arg("--profile")
        .arg("satellite")
        .arg("--packets")
        .arg("500")
        .output()
        .expect("execute chaos benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Velcrux Chaos Fault Injection Benchmark ==="));
    assert!(stdout.contains("Target Profile:      satellite"));
    assert!(stdout.contains("Simulated Packets:   500"));
    assert!(stdout.contains("Dropped Packets:"));

    // 2. JSON benchmark output (Byzantine profile asserting corrupted payloads detected)
    let output_json = Command::new(velcrux_bin())
        .arg("chaos")
        .arg("benchmark")
        .arg("--profile")
        .arg("byzantine")
        .arg("--packets")
        .arg("500")
        .arg("--json")
        .output()
        .expect("execute chaos benchmark --profile byzantine --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON benchmark report");
    assert_eq!(
        parsed.get("profile_name").and_then(|v| v.as_str()),
        Some("byzantine")
    );
    assert_eq!(
        parsed.get("total_packets").and_then(|v| v.as_u64()),
        Some(500)
    );
    assert!(
        parsed
            .get("corrupted_payloads")
            .and_then(|v| v.as_u64())
            .unwrap()
            > 0,
        "Byzantine profile must inject corrupted payloads"
    );
}

#[test]
fn test_cli_chaos_inject_text_and_json() {
    // 1. Text inject
    let output = Command::new(velcrux_bin())
        .arg("chaos")
        .arg("inject")
        .arg("--loss")
        .arg("0.05")
        .arg("--delay-ms")
        .arg("80")
        .arg("--jitter-ms")
        .arg("15")
        .output()
        .expect("execute chaos inject");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Chaos Impairment Fault Injected ==="));
    assert!(stdout.contains("Loss Rate:        5.00%"));
    assert!(stdout.contains("Latency Delay:    80 ms (±15 ms jitter)"));

    // 2. JSON inject with partition
    let output_json = Command::new(velcrux_bin())
        .arg("chaos")
        .arg("inject")
        .arg("--partition")
        .arg("--json")
        .output()
        .expect("execute chaos inject --partition --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON inject report");
    assert_eq!(
        parsed.get("blackhole_active").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[test]
fn test_gilbert_elliott_burst_loss_clustering() {
    let config = GilbertElliottConfig {
        p: 0.05,
        r: 0.20,
        loss_in_good: 0.0,
        loss_in_bad: 1.0,
    };
    let mut model = GilbertElliottModel::new(config);
    let mut prng = ChaosPrng::new(999);

    let mut burst_lengths = Vec::new();
    let mut current_burst = 0;

    for _ in 0..2000 {
        let dropped = model.step(&mut prng);
        if dropped {
            current_burst += 1;
        } else if current_burst > 0 {
            burst_lengths.push(current_burst);
            current_burst = 0;
        }
    }

    assert!(
        !burst_lengths.is_empty(),
        "Gilbert-Elliott model must produce burst loss events"
    );
    let avg_burst: f64 = burst_lengths.iter().sum::<usize>() as f64 / burst_lengths.len() as f64;
    // Expected burst length 1/r = 1/0.20 = 5.0 packets
    assert!(
        avg_burst >= 2.0 && avg_burst <= 8.0,
        "average burst length should be near theoretical expectation (~5.0), got {avg_burst}"
    );
}

#[test]
fn test_byzantine_corruption_stress_verification() {
    let config = ChaosConfig {
        enabled: true,
        loss_rate: 0.0,
        burst_loss: None,
        delay_ms: 0,
        jitter_ms: 0,
        reorder_rate: 0.0,
        reorder_delay_ms: 0,
        duplicate_rate: 0.0,
        corrupt_rate: 1.0, // 100% corruption
        blackhole: false,
    };
    let engine = ChaosEngine::new(config, 42);

    let original = b"production-dataset-chunk-content-for-blake3";
    let original_hash = Hash::of(original);

    match engine.process_packet(original) {
        ChaosOutcome::Pass { payload, .. } => {
            let corrupted_hash = Hash::of(&payload);
            assert_ne!(
                original_hash, corrupted_hash,
                "BLAKE3 digest of corrupted payload must differ from original"
            );
        }
        other => panic!("expected Pass outcome, got {other:?}"),
    }
}
