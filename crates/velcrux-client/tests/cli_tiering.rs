//! Integration tests for Option BY: Multi-Tenant Hierarchical Storage Tiering & Hybrid Lifecycle Engine (`ADR-041`).

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;
use velcrux_core::storage::{StorageTier, TenantTierPolicy, TieredStorageManager};
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
fn test_cli_tier_status_text_and_json() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let mgr = TieredStorageManager::new(&store_dir).unwrap();

    let data = b"Sample tiered store chunk payload for status report test";
    let hash = Hash::of(data);
    mgr.put("tenant_alpha", &hash, data).unwrap();

    // 1. Text format
    let output = Command::new(velcrux_bin())
        .arg("tier")
        .arg("status")
        .arg("--chunk-store")
        .arg(&store_dir)
        .output()
        .expect("execute tier status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Hierarchical Storage Tiering Status ==="));
    assert!(stdout.contains("Hot Tier (NVMe/SSD):"));
    assert!(stdout.contains("Warm Tier (Bulk):"));
    assert!(stdout.contains("Cold Tier (Archive):"));
    assert!(stdout.contains("Space Savings Ratio:"));

    // 2. JSON format
    let output_json = Command::new(velcrux_bin())
        .arg("tier")
        .arg("status")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute tier status --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON status report");
    assert_eq!(parsed.get("hot_chunks").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(parsed.get("warm_chunks").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(parsed.get("cold_chunks").and_then(|v| v.as_u64()), Some(0));
}

#[test]
fn test_cli_tier_policy_set_get_list() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("store");

    // 1. Set policy for tenant_gamma
    let output_set = Command::new(velcrux_bin())
        .arg("tier")
        .arg("policy")
        .arg("set")
        .arg("--tenant")
        .arg("tenant_gamma")
        .arg("--hot-days")
        .arg("3")
        .arg("--warm-days")
        .arg("14")
        .arg("--cold-retention-days")
        .arg("90")
        .arg("--max-hot-bytes")
        .arg("10485760")
        .arg("--compression-level")
        .arg("7")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute policy set");

    assert!(
        output_set.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_set.stderr)
    );
    let parsed_set: serde_json::Value =
        serde_json::from_slice(&output_set.stdout).expect("valid JSON policy response");
    assert_eq!(
        parsed_set.get("tenant_id").and_then(|v| v.as_str()),
        Some("tenant_gamma")
    );
    assert_eq!(
        parsed_set.get("hot_to_warm_days").and_then(|v| v.as_u64()),
        Some(3)
    );
    assert_eq!(
        parsed_set.get("warm_to_cold_days").and_then(|v| v.as_u64()),
        Some(14)
    );
    assert_eq!(
        parsed_set
            .get("cold_retention_days")
            .and_then(|v| v.as_u64()),
        Some(90)
    );

    // 2. Get policy for tenant_gamma
    let output_get = Command::new(velcrux_bin())
        .arg("tier")
        .arg("policy")
        .arg("get")
        .arg("--tenant")
        .arg("tenant_gamma")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute policy get");

    assert!(output_get.status.success());
    let parsed_get: serde_json::Value =
        serde_json::from_slice(&output_get.stdout).expect("valid JSON get response");
    assert_eq!(
        parsed_get.get("tenant_id").and_then(|v| v.as_str()),
        Some("tenant_gamma")
    );

    // 3. List all policies
    let output_list = Command::new(velcrux_bin())
        .arg("tier")
        .arg("policy")
        .arg("list")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute policy list");

    assert!(output_list.status.success());
    let parsed_list: Vec<serde_json::Value> =
        serde_json::from_slice(&output_list.stdout).expect("valid JSON list response");
    assert!(parsed_list
        .iter()
        .any(|p| p.get("tenant_id").and_then(|v| v.as_str()) == Some("tenant_gamma")));
}

#[test]
fn test_cli_tier_migrate_hot_warm_cold() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let mgr = TieredStorageManager::new(&store_dir).unwrap();

    let data = b"Chunk payload for manual tier migration validation";
    let hash = Hash::of(data);
    mgr.put("tenant_delta", &hash, data).unwrap();
    assert_eq!(mgr.has(&hash).unwrap(), Some(StorageTier::Hot));

    // Migrate to Warm tier via CLI
    let output_warm = Command::new(velcrux_bin())
        .arg("tier")
        .arg("migrate")
        .arg("--hash")
        .arg(hash.to_hex())
        .arg("--target")
        .arg("warm")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute tier migrate warm");

    assert!(
        output_warm.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_warm.stderr)
    );
    let parsed_warm: serde_json::Value =
        serde_json::from_slice(&output_warm.stdout).expect("valid JSON migrate response");
    assert_eq!(
        parsed_warm.get("success").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        parsed_warm.get("target_tier").and_then(|v| v.as_str()),
        Some("warm")
    );

    // Migrate to Cold tier via CLI
    let output_cold = Command::new(velcrux_bin())
        .arg("tier")
        .arg("migrate")
        .arg("--hash")
        .arg(hash.to_hex())
        .arg("--target")
        .arg("cold")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute tier migrate cold");

    assert!(output_cold.status.success());
    let parsed_cold: serde_json::Value =
        serde_json::from_slice(&output_cold.stdout).expect("valid JSON migrate cold response");
    assert_eq!(
        parsed_cold.get("target_tier").and_then(|v| v.as_str()),
        Some("cold")
    );

    // Verify chunk is stored compressed with .zst extension
    let cold_file = mgr.chunk_path(&hash, StorageTier::Cold);
    assert!(cold_file.exists());
    assert!(cold_file.to_string_lossy().ends_with(".zst"));
}

#[test]
fn test_cli_tier_lifecycle_sweep() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let mgr = TieredStorageManager::new(&store_dir).unwrap();

    // Set immediate demotion policy for tenant_eps
    let policy = TenantTierPolicy {
        tenant_id: "tenant_eps".to_string(),
        hot_to_warm_days: 0,
        warm_to_cold_days: 0,
        cold_retention_days: None,
        max_hot_bytes: Some(5), // low quota triggers eviction
        auto_promote_on_read: false,
        cold_compression_level: 3,
    };
    mgr.set_tenant_policy(policy).unwrap();

    let data = b"Longer text payload that compresses well for lifecycle sweep testing and cold Zstd storage evaluation.";
    let hash = Hash::of(data);
    mgr.put("tenant_eps", &hash, data).unwrap();

    // Run sweep via CLI in dry run mode
    let output_dry = Command::new(velcrux_bin())
        .arg("tier")
        .arg("sweep")
        .arg("--tenant")
        .arg("tenant_eps")
        .arg("--dry-run")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute tier sweep --dry-run");

    assert!(output_dry.status.success());
    let parsed_dry: serde_json::Value =
        serde_json::from_slice(&output_dry.stdout).expect("valid JSON dry run sweep report");
    assert_eq!(
        parsed_dry.get("dry_run").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        parsed_dry.get("chunks_scanned").and_then(|v| v.as_u64()),
        Some(1)
    );

    // Run real sweep via CLI
    let output_real = Command::new(velcrux_bin())
        .arg("tier")
        .arg("sweep")
        .arg("--tenant")
        .arg("tenant_eps")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute tier sweep real");

    assert!(output_real.status.success());
    let parsed_real: serde_json::Value =
        serde_json::from_slice(&output_real.stdout).expect("valid JSON real sweep report");
    assert_eq!(
        parsed_real.get("dry_run").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert!(
        parsed_real
            .get("hot_to_warm_migrated")
            .and_then(|v| v.as_u64())
            .unwrap()
            > 0
    );
}

#[test]
fn test_cli_tier_scrub_cold_integrity() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let mgr = TieredStorageManager::new(&store_dir).unwrap();

    let data = b"Cryptographic scrub verification payload for tiered store testing";
    let hash = Hash::of(data);
    mgr.put("tenant_zeta", &hash, data).unwrap();
    mgr.migrate_chunk(&hash, StorageTier::Cold).unwrap();

    // 1. Clean scrub
    let output_clean = Command::new(velcrux_bin())
        .arg("tier")
        .arg("scrub")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute tier scrub");

    assert!(output_clean.status.success());
    let parsed_clean: serde_json::Value =
        serde_json::from_slice(&output_clean.stdout).expect("valid JSON scrub report");
    assert_eq!(
        parsed_clean.get("chunks_scanned").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        parsed_clean.get("valid_chunks").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        parsed_clean
            .get("corrupt_chunks")
            .and_then(|v| v.as_array())
            .unwrap()
            .len(),
        0
    );

    // 2. Corrupt cold archive and scrub again
    let cold_path = mgr.chunk_path(&hash, StorageTier::Cold);
    let mut raw_bytes = fs::read(&cold_path).unwrap();
    if let Some(b) = raw_bytes.last_mut() {
        *b ^= 0xFF;
    }
    fs::write(&cold_path, raw_bytes).unwrap();

    let output_corrupt = Command::new(velcrux_bin())
        .arg("tier")
        .arg("scrub")
        .arg("--chunk-store")
        .arg(&store_dir)
        .arg("--json")
        .output()
        .expect("execute tier scrub with corruption");

    assert!(output_corrupt.status.success());
    let parsed_corrupt: serde_json::Value =
        serde_json::from_slice(&output_corrupt.stdout).expect("valid JSON scrub report");
    assert_eq!(
        parsed_corrupt.get("valid_chunks").and_then(|v| v.as_u64()),
        Some(0)
    );
    assert_eq!(
        parsed_corrupt
            .get("corrupt_chunks")
            .and_then(|v| v.as_array())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_tiered_store_transparent_read_and_promotion() {
    let dir = tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let mgr = TieredStorageManager::new(&store_dir).unwrap();

    let data = b"Transparent read and promotion test payload across hierarchical storage layers.";
    let hash = Hash::of(data);

    // Put into Hot tier
    mgr.put("tenant_theta", &hash, data).unwrap();

    // Demote directly to Cold tier
    mgr.migrate_chunk(&hash, StorageTier::Cold).unwrap();
    assert_eq!(mgr.has(&hash).unwrap(), Some(StorageTier::Cold));

    // Transparent read decompresses and auto-promotes to Hot tier
    let retrieved = mgr.get("tenant_theta", &hash).unwrap();
    assert_eq!(&retrieved[..], data);
    assert_eq!(mgr.has(&hash).unwrap(), Some(StorageTier::Hot));
}
