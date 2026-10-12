//! Integration tests for `velcrux plan` and safe delete CLI semantics (`REQUIREMENTS.md` §57–§61).

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
fn test_cli_plan_subcommand_display_and_json() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("file_a.txt"), b"file a contents").unwrap();
    fs::write(src.join("file_b.txt"), b"file b contents").unwrap();
    fs::write(dst.join("file_a.txt"), b"file a contents").unwrap();
    fs::write(dst.join("file_c.txt"), b"extraneous file c").unwrap();

    // 1. Test standard ASCII formatted plan
    let output = Command::new(velcrux_bin())
        .arg("plan")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--delete-after")
        .output()
        .expect("failed to execute velcrux plan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("VELCRUX TRANSFER PLAN"));
    assert!(stdout.contains("Files unchanged"));
    assert!(stdout.contains("Files added"));
    assert!(stdout.contains("Files deleted"));
    assert!(stdout.contains("Data already present"));
    assert!(stdout.contains("Data to transfer"));

    // 2. Test machine-readable JSON plan output
    let output_json = Command::new(velcrux_bin())
        .arg("--json")
        .arg("plan")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux --json plan");

    assert!(output_json.status.success());
    let stdout_json = String::from_utf8_lossy(&output_json.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout_json).expect("valid JSON expected from --json plan");

    assert_eq!(parsed["event"], "transfer_plan");
    assert_eq!(parsed["summary"]["files_unchanged"], 1);
    assert_eq!(parsed["summary"]["files_added"], 1);
    assert_eq!(parsed["summary"]["files_deleted"], 1);
}

#[test]
fn test_cli_sync_delete_before() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("incoming.dat"), b"incoming data payload").unwrap();
    fs::write(dst.join("legacy.dat"), b"legacy data payload").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--delete-before")
        .output()
        .expect("failed to execute velcrux sync --delete-before");

    assert!(output.status.success());
    assert!(dst.join("incoming.dat").exists());
    assert!(!dst.join("legacy.dat").exists());
}

#[test]
fn test_cli_sync_delete_guardrails_abort_and_force() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("live.txt"), b"live").unwrap();
    fs::write(dst.join("del1.txt"), b"del1").unwrap();
    fs::write(dst.join("del2.txt"), b"del2").unwrap();
    fs::write(dst.join("del3.txt"), b"del3").unwrap();

    // 1. Without force-delete: abort when max-delete is 1
    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--delete")
        .arg("--max-delete")
        .arg("1")
        .output()
        .expect("failed to execute velcrux sync with max-delete");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Deletion guardrail triggered") || stderr.contains("exceeds safety threshold"));

    // Verify destination files were NOT deleted
    assert!(dst.join("del1.txt").exists());
    assert!(dst.join("del2.txt").exists());
    assert!(dst.join("del3.txt").exists());

    // 2. With --force-delete: succeed and bypass limit
    let output_force = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--delete")
        .arg("--max-delete")
        .arg("1")
        .arg("--force-delete")
        .output()
        .expect("failed to execute velcrux sync with force-delete");

    assert!(output_force.status.success());
    assert!(!dst.join("del1.txt").exists());
    assert!(!dst.join("del2.txt").exists());
    assert!(!dst.join("del3.txt").exists());
    assert!(dst.join("live.txt").exists());
}

#[test]
fn test_cli_sync_exclude_and_delete_excluded() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("code.rs"), b"fn main() {}").unwrap();
    fs::write(src.join("build.tmp"), b"transient").unwrap();

    fs::write(dst.join("code.rs"), b"fn main() {}").unwrap();
    fs::write(dst.join("build.tmp"), b"old transient").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--exclude")
        .arg("*.tmp")
        .arg("--delete-excluded")
        .output()
        .expect("failed to execute velcrux sync --exclude --delete-excluded");

    assert!(output.status.success());
    assert!(dst.join("code.rs").exists());
    assert!(!dst.join("build.tmp").exists());
}
