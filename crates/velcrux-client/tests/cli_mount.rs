//! Integration tests for Virtual Filesystem Mount CLI commands (Option BL).

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
fn test_cli_mount_attach_list_status_detach() {
    let temp = tempdir().unwrap();
    let reg_file = temp.path().join("test_registry_1.json");
    let src_dir = temp.path().join("source_dataset");
    let mnt_dir = temp.path().join("vfs_mountpoint");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("sample.txt"),
        b"Velcrux mount engine test file",
    )
    .unwrap();

    // 1. Attach mount
    let attach_out = Command::new(velcrux_bin())
        .env("VELCRUX_MOUNT_REGISTRY", &reg_file)
        .arg("mount")
        .arg("attach")
        .arg(src_dir.to_str().unwrap())
        .arg(mnt_dir.to_str().unwrap())
        .arg("--cache-size-mb")
        .arg("128")
        .arg("--prefetch")
        .arg("4")
        .output()
        .expect("execute mount attach");

    assert!(
        attach_out.status.success(),
        "mount attach failed: {:?}",
        String::from_utf8_lossy(&attach_out.stderr)
    );
    let attach_str = String::from_utf8_lossy(&attach_out.stdout);
    assert!(attach_str.contains("Velcrux Virtual Filesystem (VFS) Mounted Successfully"));
    assert!(attach_str.contains("Access Mode:     Read-Only (RO)"));
    assert!(attach_str.contains("128 MiB"));
    assert!(attach_str.contains("Prefetch: 4 chunks"));

    // 2. Mount list (table format)
    let list_out = Command::new(velcrux_bin())
        .env("VELCRUX_MOUNT_REGISTRY", &reg_file)
        .arg("mount")
        .arg("list")
        .output()
        .expect("execute mount list");

    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("SESSION ID"));
    assert!(list_str.contains("MOUNTPOINT"));
    assert!(list_str.contains(mnt_dir.to_str().unwrap()));

    // 3. Mount list (--json format)
    let list_json_out = Command::new(velcrux_bin())
        .env("VELCRUX_MOUNT_REGISTRY", &reg_file)
        .arg("--json")
        .arg("mount")
        .arg("list")
        .output()
        .expect("execute mount list --json");

    assert!(list_json_out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&list_json_out.stdout).expect("parse json");
    let arr = parsed.as_array().expect("json array of mounts");
    assert!(arr.iter().any(|s| s["mountpoint"]
        .as_str()
        .unwrap_or("")
        .contains(mnt_dir.to_str().unwrap())));

    // 4. Mount status
    let status_out = Command::new(velcrux_bin())
        .env("VELCRUX_MOUNT_REGISTRY", &reg_file)
        .arg("mount")
        .arg("status")
        .arg("--mountpoint")
        .arg(mnt_dir.to_str().unwrap())
        .output()
        .expect("execute mount status");

    assert!(status_out.status.success());
    let status_str = String::from_utf8_lossy(&status_out.stdout);
    assert!(status_str.contains("Virtual Mount Session:"));
    assert!(status_str.contains(mnt_dir.to_str().unwrap()));

    // 5. Mount detach
    let detach_out = Command::new(velcrux_bin())
        .env("VELCRUX_MOUNT_REGISTRY", &reg_file)
        .arg("mount")
        .arg("detach")
        .arg(mnt_dir.to_str().unwrap())
        .output()
        .expect("execute mount detach");

    assert!(detach_out.status.success());
    let detach_str = String::from_utf8_lossy(&detach_out.stdout);
    assert!(detach_str.contains("Successfully unmounted"));
}

#[test]
fn test_cli_mount_json_mode_and_unmount_command() {
    let temp = tempdir().unwrap();
    let reg_file = temp.path().join("test_registry_2.json");
    let mnt_dir = temp.path().join("cloud_mountpoint");

    // 1. Mount attach in json mode
    let attach_out = Command::new(velcrux_bin())
        .env("VELCRUX_MOUNT_REGISTRY", &reg_file)
        .arg("--json")
        .arg("mount")
        .arg("attach")
        .arg("s3://dataset-bucket/production-runs/")
        .arg(mnt_dir.to_str().unwrap())
        .arg("--read-only")
        .arg("false")
        .output()
        .expect("execute mount attach json");

    assert!(attach_out.status.success());
    let attach_json: serde_json::Value =
        serde_json::from_slice(&attach_out.stdout).expect("parse json");
    assert_eq!(attach_json["status"], "mounted");
    assert_eq!(
        attach_json["source"],
        "s3://dataset-bucket/production-runs/"
    );
    assert_eq!(attach_json["read_only"], false);

    // 2. Unmount using top-level `velcrux unmount`
    let unmount_out = Command::new(velcrux_bin())
        .env("VELCRUX_MOUNT_REGISTRY", &reg_file)
        .arg("unmount")
        .arg(mnt_dir.to_str().unwrap())
        .output()
        .expect("execute top-level unmount");

    assert!(unmount_out.status.success());
    let unmount_str = String::from_utf8_lossy(&unmount_out.stdout);
    assert!(unmount_str.contains("Successfully unmounted"));

    // 3. Verify status indicates no active mount
    let status_out = Command::new(velcrux_bin())
        .env("VELCRUX_MOUNT_REGISTRY", &reg_file)
        .arg("mount")
        .arg("status")
        .arg("--mountpoint")
        .arg(mnt_dir.to_str().unwrap())
        .output()
        .expect("execute status");

    assert!(status_out.status.success());
    let status_str = String::from_utf8_lossy(&status_out.stdout);
    assert!(status_str.contains("No active virtual mount found"));
}
