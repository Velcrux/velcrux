//! Integration tests for point-in-time snapshot isolation CLI (Option BC).

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
fn test_cli_snapshot_lifecycle_table() {
    let tmp = tempdir().unwrap();
    let src_dir = tmp.path().join("source");
    let cas_dir = tmp.path().join("cas");
    let restore_dir = tmp.path().join("restored");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("file1.txt"), b"Hello from Snapshot CLI test file 1").unwrap();
    fs::write(src_dir.join("file2.bin"), vec![0x42; 4096]).unwrap();

    // 1. Create snapshot snap-v1
    let output = Command::new(velcrux_bin())
        .arg("snapshot")
        .arg("create")
        .arg("snap-v1")
        .arg(&src_dir)
        .arg("--chunk-store")
        .arg(&cas_dir)
        .arg("--desc")
        .arg("Initial baseline snapshot")
        .output()
        .expect("execute velcrux snapshot create");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("POINT-IN-TIME DIRECTORY SNAPSHOT CREATED"));
    assert!(stdout.contains("Snapshot Tag         : snap-v1"));
    assert!(stdout.contains("Captured Files       : 2"));
    assert!(stdout.contains("CAS Active (Chunked)"));

    // 2. List snapshots
    let output_list = Command::new(velcrux_bin())
        .arg("snapshot")
        .arg("list")
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux snapshot list");

    assert!(output_list.status.success());
    let stdout_list = String::from_utf8_lossy(&output_list.stdout);
    assert!(stdout_list.contains("POINT-IN-TIME DATASET SNAPSHOT CATALOG"));
    assert!(stdout_list.contains("snap-v1"));
    assert!(stdout_list.contains("Total Snapshots: 1"));

    // 3. Mutate source and create snap-v2
    fs::write(src_dir.join("file1.txt"), b"Modified text in file 1").unwrap();
    fs::write(src_dir.join("file3.rs"), b"fn main() {}").unwrap();

    let output_v2 = Command::new(velcrux_bin())
        .arg("snapshot")
        .arg("create")
        .arg("snap-v2")
        .arg(&src_dir)
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux snapshot create v2");
    assert!(output_v2.status.success());

    // 4. Diff snap-v1 and snap-v2
    let output_diff = Command::new(velcrux_bin())
        .arg("snapshot")
        .arg("diff")
        .arg("snap-v1")
        .arg("snap-v2")
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux snapshot diff");

    assert!(output_diff.status.success());
    let stdout_diff = String::from_utf8_lossy(&output_diff.stdout);
    assert!(stdout_diff.contains("SNAPSHOT DIFFERENCE REPORT: snap-v1 -> snap-v2"));
    assert!(stdout_diff.contains("Files Added          : 1"));
    assert!(stdout_diff.contains("file3.rs"));
    assert!(stdout_diff.contains("Files Modified       : 1"));
    assert!(stdout_diff.contains("file1.txt"));
    assert!(stdout_diff.contains("Files Unchanged      : 1"));

    // 5. Restore snap-v1 to restore_dir
    let output_restore = Command::new(velcrux_bin())
        .arg("snapshot")
        .arg("restore")
        .arg("snap-v1")
        .arg("--dest")
        .arg(&restore_dir)
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux snapshot restore");

    assert!(output_restore.status.success());
    let stdout_restore = String::from_utf8_lossy(&output_restore.stdout);
    assert!(stdout_restore.contains("POINT-IN-TIME SNAPSHOT RESTORED"));
    assert!(stdout_restore.contains("Restored Files       : 2"));
    assert!(stdout_restore.contains("100% BLAKE3 Verified"));
    assert_eq!(fs::read(restore_dir.join("file1.txt")).unwrap(), b"Hello from Snapshot CLI test file 1");

    // 6. Delete snapshot snap-v1
    let output_del = Command::new(velcrux_bin())
        .arg("snapshot")
        .arg("delete")
        .arg("snap-v1")
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux snapshot delete");

    assert!(output_del.status.success());
    assert!(String::from_utf8_lossy(&output_del.stdout).contains("Snapshot 'snap-v1' deleted successfully."));
}

#[test]
fn test_cli_snapshot_json() {
    let tmp = tempdir().unwrap();
    let src_dir = tmp.path().join("source");
    let cas_dir = tmp.path().join("cas");
    let restore_dir = tmp.path().join("restored");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("json_test.txt"), b"Data for JSON testing").unwrap();

    // 1. JSON Create
    let output_create = Command::new(velcrux_bin())
        .arg("--json")
        .arg("snapshot")
        .arg("create")
        .arg("snap-json-1")
        .arg(&src_dir)
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux --json snapshot create");

    assert!(output_create.status.success());
    let val_create: serde_json::Value =
        serde_json::from_slice(&output_create.stdout).expect("valid JSON expected");
    assert_eq!(val_create["event"], "snapshot_created");
    assert_eq!(val_create["tag"], "snap-json-1");
    assert_eq!(val_create["file_count"], 1);

    // 2. JSON List
    let output_list = Command::new(velcrux_bin())
        .arg("--json")
        .arg("snapshot")
        .arg("list")
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux --json snapshot list");

    assert!(output_list.status.success());
    let val_list: serde_json::Value =
        serde_json::from_slice(&output_list.stdout).expect("valid JSON expected");
    assert_eq!(val_list["event"], "snapshot_list");
    assert_eq!(val_list["total_snapshots"], 1);

    // 3. JSON Restore
    let output_restore = Command::new(velcrux_bin())
        .arg("--json")
        .arg("snapshot")
        .arg("restore")
        .arg("snap-json-1")
        .arg("--dest")
        .arg(&restore_dir)
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux --json snapshot restore");

    assert!(output_restore.status.success());
    let val_restore: serde_json::Value =
        serde_json::from_slice(&output_restore.stdout).expect("valid JSON expected");
    assert_eq!(val_restore["event"], "snapshot_restored");
    assert_eq!(val_restore["report"]["tag"], "snap-json-1");
    assert_eq!(val_restore["report"]["restored_files"], 1);

    // 4. JSON Delete
    let output_del = Command::new(velcrux_bin())
        .arg("--json")
        .arg("snapshot")
        .arg("delete")
        .arg("snap-json-1")
        .arg("--chunk-store")
        .arg(&cas_dir)
        .output()
        .expect("execute velcrux --json snapshot delete");

    assert!(output_del.status.success());
    let val_del: serde_json::Value =
        serde_json::from_slice(&output_del.stdout).expect("valid JSON expected");
    assert_eq!(val_del["event"], "snapshot_deleted");
    assert_eq!(val_del["tag"], "snap-json-1");
    assert_eq!(val_del["deleted"], true);
}
