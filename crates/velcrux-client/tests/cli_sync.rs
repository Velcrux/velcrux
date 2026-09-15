//! Integration tests for `velcrux sync` CLI subcommand (`REQUIREMENTS.md` §58–§60).

use std::process::Command;
use tempfile::tempdir;

fn velcrux_bin() -> std::path::PathBuf {
    // Locate the built `velcrux` binary in target/debug
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // exit test exe
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_sync_dry_run() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // 1. Unchanged file
    std::fs::write(src.join("unchanged.txt"), b"unchanged data").unwrap();
    std::fs::write(dst.join("unchanged.txt"), b"unchanged data").unwrap();

    // 2. Modified file
    std::fs::write(src.join("modified.txt"), b"new modified version").unwrap();
    std::fs::write(dst.join("modified.txt"), b"old version").unwrap();

    // 3. Added file
    std::fs::write(src.join("added.txt"), b"added content").unwrap();

    // 4. Extraneous file on destination
    std::fs::write(dst.join("orphan.txt"), b"orphan content").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--dry-run")
        .output()
        .expect("failed to execute velcrux sync --dry-run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("--- CLI Dry-Run Output ---\n{stdout}");

    // Verify format matches REQUIREMENTS.md §58
    assert!(stdout.contains("Files unchanged:"));
    assert!(stdout.contains("Files modified:"));
    assert!(stdout.contains("Files added:"));
    assert!(stdout.contains("Files deleted:"));
    assert!(stdout.contains("Data already present:"));
    assert!(stdout.contains("Data to transfer:"));
    assert!(stdout.contains("Estimated reduction:"));

    // Verify destination was NOT modified
    assert!(!dst.join("added.txt").exists());
    assert_eq!(std::fs::read(dst.join("modified.txt")).unwrap(), b"old version");
    assert!(dst.join("orphan.txt").exists());
}

#[test]
fn test_cli_sync_full_execute_and_delete_modes() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("file1.txt"), b"file 1 content").unwrap();
    std::fs::write(src.join("file2.txt"), b"file 2 content").unwrap();
    std::fs::write(dst.join("orphan.txt"), b"orphan file").unwrap();

    // 1. Run default sync (no delete)
    let output1 = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux sync");

    assert!(output1.status.success());
    assert_eq!(std::fs::read(dst.join("file1.txt")).unwrap(), b"file 1 content");
    assert_eq!(std::fs::read(dst.join("file2.txt")).unwrap(), b"file 2 content");
    assert!(
        dst.join("orphan.txt").exists(),
        "orphan.txt must be preserved under default DeleteMode::None"
    );

    // 2. Run sync with --delete-after
    let output2 = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--delete-after")
        .output()
        .expect("failed to execute velcrux sync --delete-after");

    assert!(output2.status.success());
    assert_eq!(std::fs::read(dst.join("file1.txt")).unwrap(), b"file 1 content");
    assert_eq!(std::fs::read(dst.join("file2.txt")).unwrap(), b"file 2 content");
    assert!(
        !dst.join("orphan.txt").exists(),
        "orphan.txt must be deleted under --delete-after"
    );
}

#[test]
fn test_cli_sync_cdc_and_dedup() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    let chunk_store = temp.path().join("chunk_store");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("payload.dat"), b"dedup test payload data").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--cdc")
        .arg("--dedup")
        .arg("--chunk-store")
        .arg(chunk_store.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux sync --cdc --dedup");

    assert!(output.status.success());
    assert_eq!(
        std::fs::read(dst.join("payload.dat")).unwrap(),
        b"dedup test payload data"
    );
}
