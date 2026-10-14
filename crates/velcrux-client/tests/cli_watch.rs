//! Integration tests for real-time continuous directory watching CLI (Option AZ).

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
fn test_cli_watch_bounded_batches() {
    let src = tempdir().unwrap();
    let dst = tempdir().unwrap();

    // Seed file in source directory
    fs::write(src.path().join("watch_doc.txt"), b"initial watch text").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("watch")
        .arg(src.path())
        .arg(dst.path())
        .arg("--debounce-ms")
        .arg("50")
        .arg("--poll-interval-ms")
        .arg("20")
        .arg("--max-batches")
        .arg("1")
        .arg("--initial-sync")
        .output()
        .expect("execute velcrux watch");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("VELCRUX REAL-TIME CONTINUOUS FILE WATCHER & SYNC"));
    assert!(stdout.contains("Debounce Window      : 50 ms"));
    assert!(stdout.contains("Execution Mode       : Bounded (Max 1 batches)"));
    assert!(stdout.contains("CONTINUOUS WATCH SYNCHRONIZATION SUMMARY"));
    assert!(stdout.contains("Total Sync Batches   : 1"));

    // Verify destination received file
    assert!(dst.path().join("watch_doc.txt").exists());
}

#[test]
fn test_cli_watch_json_output() {
    let src = tempdir().unwrap();
    let dst = tempdir().unwrap();

    fs::write(src.path().join("data.json"), b"{\"status\":\"active\"}").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("watch")
        .arg(src.path())
        .arg(dst.path())
        .arg("--debounce-ms")
        .arg("50")
        .arg("--poll-interval-ms")
        .arg("20")
        .arg("--max-batches")
        .arg("1")
        .arg("--initial-sync")
        .output()
        .expect("execute velcrux --json watch");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify JSON lines or output
    assert!(stdout.contains("\"total_batches\": 1"));
    assert!(stdout.contains("\"status\": \"Completed\""));
    assert!(dst.path().join("data.json").exists());
}

#[test]
fn test_cli_sync_with_watch_flag() {
    let src = tempdir().unwrap();
    let dst = tempdir().unwrap();

    fs::write(src.path().join("stream.dat"), b"streamed bytes").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.path())
        .arg(dst.path())
        .arg("--watch")
        .arg("--debounce-ms")
        .arg("50")
        .arg("--poll-interval-ms")
        .arg("20")
        .arg("--max-batches")
        .arg("1")
        .output()
        .expect("execute velcrux sync --watch");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX REAL-TIME CONTINUOUS FILE WATCHER & SYNC"));
    assert!(stdout.contains("CONTINUOUS WATCH SYNCHRONIZATION SUMMARY"));
}
