//! CLI integration tests for whole-directory transactional commit and rollback journaling (Option BM).

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
fn test_cli_sync_atomic_success_and_json() {
    let src = tempdir().unwrap();
    let dst = tempdir().unwrap();

    fs::write(src.path().join("alpha.txt"), b"alpha content").unwrap();
    fs::write(src.path().join("beta.dat"), b"beta content").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.path())
        .arg(dst.path())
        .arg("--atomic")
        .arg("--log-format")
        .arg("json")
        .output()
        .expect("execute velcrux sync --atomic");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");

    assert_eq!(parsed["atomic"], true);
    assert!(parsed["transaction_id"].is_string());
    assert_eq!(parsed["files_committed"], 2);

    assert_eq!(
        fs::read(dst.path().join("alpha.txt")).unwrap(),
        b"alpha content"
    );
    assert_eq!(
        fs::read(dst.path().join("beta.dat")).unwrap(),
        b"beta content"
    );
}

#[test]
fn test_cli_tx_list_and_show() {
    let src = tempdir().unwrap();
    let dst = tempdir().unwrap();

    fs::write(src.path().join("manifest.cfg"), b"setting=true").unwrap();

    // 1. Sync atomically
    let sync_out = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.path())
        .arg(dst.path())
        .arg("--atomic")
        .arg("--log-format")
        .arg("json")
        .output()
        .expect("sync");
    assert!(sync_out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&sync_out.stdout)).unwrap();
    let tx_id = parsed["transaction_id"].as_str().unwrap();

    // 2. Run velcrux tx list
    let list_out = Command::new(velcrux_bin())
        .arg("tx")
        .arg("list")
        .arg(dst.path())
        .output()
        .expect("tx list");
    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("TRANSACTION ID"));
    assert!(list_str.contains(tx_id));
    assert!(list_str.contains("Committed"));

    // 3. Run velcrux tx show
    let show_out = Command::new(velcrux_bin())
        .arg("tx")
        .arg("show")
        .arg(tx_id)
        .arg("--path")
        .arg(dst.path())
        .output()
        .expect("tx show");
    assert!(show_out.status.success());
    let show_str = String::from_utf8_lossy(&show_out.stdout);
    assert!(show_str.contains("Transaction ID:"));
    assert!(show_str.contains(tx_id));
    assert!(show_str.contains("manifest.cfg"));
}

#[test]
fn test_cli_tx_rollback_workflow() {
    let src = tempdir().unwrap();
    let dst = tempdir().unwrap();

    // Original destination file
    fs::write(dst.path().join("service.conf"), b"port=8080").unwrap();

    // Updated in source
    fs::write(src.path().join("service.conf"), b"port=9090").unwrap();
    fs::write(src.path().join("new_feature.txt"), b"feature active").unwrap();

    // 1. Execute atomic sync
    let sync_out = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.path())
        .arg(dst.path())
        .arg("--atomic")
        .arg("--log-format")
        .arg("json")
        .output()
        .expect("sync");
    assert!(sync_out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&sync_out.stdout)).unwrap();
    let tx_id = parsed["transaction_id"].as_str().unwrap();

    assert_eq!(
        fs::read(dst.path().join("service.conf")).unwrap(),
        b"port=9090"
    );
    assert_eq!(
        fs::read(dst.path().join("new_feature.txt")).unwrap(),
        b"feature active"
    );

    // 2. Roll back via CLI
    let rollback_out = Command::new(velcrux_bin())
        .arg("tx")
        .arg("rollback")
        .arg(tx_id)
        .arg("--path")
        .arg(dst.path())
        .output()
        .expect("tx rollback");
    assert!(rollback_out.status.success());
    let rb_str = String::from_utf8_lossy(&rollback_out.stdout);
    assert!(rb_str.contains("Successfully rolled back transaction"));

    // 3. Destination restored to baseline
    assert_eq!(
        fs::read(dst.path().join("service.conf")).unwrap(),
        b"port=8080"
    );
    assert!(!dst.path().join("new_feature.txt").exists());
}

#[test]
fn test_cli_tx_recover_clean() {
    let dst = tempdir().unwrap();

    let output = Command::new(velcrux_bin())
        .arg("tx")
        .arg("recover")
        .arg(dst.path())
        .output()
        .expect("tx recover");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No pending or crashed transactions to recover"));
}
