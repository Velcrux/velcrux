//! Integration tests for S3 object storage CLI (`REQUIREMENTS.md` §42, §43).

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
fn test_cli_s3_put_stat_ls_get_delete() {
    let temp = tempdir().unwrap();
    let local_file = temp.path().join("payload.txt");
    fs::write(&local_file, b"Velcrux S3 Object Storage Gateway").unwrap();

    let dl_file = temp.path().join("downloaded.txt");

    // 1. Put object
    let put_out = Command::new(velcrux_bin())
        .arg("s3")
        .arg("put")
        .arg(local_file.to_str().unwrap())
        .arg("s3://test-cli-bucket/test/payload.txt")
        .output()
        .expect("execute s3 put");

    assert!(put_out.status.success(), "s3 put failed: {:?}", String::from_utf8_lossy(&put_out.stderr));
    let put_str = String::from_utf8_lossy(&put_out.stdout);
    assert!(put_str.contains("Successfully uploaded"));

    // 2. Stat object
    let stat_out = Command::new(velcrux_bin())
        .arg("s3")
        .arg("stat")
        .arg("s3://test-cli-bucket/test/payload.txt")
        .output()
        .expect("execute s3 stat");

    assert!(stat_out.status.success());
    let stat_str = String::from_utf8_lossy(&stat_out.stdout);
    assert!(stat_str.contains("S3 Object Metadata: s3://test-cli-bucket/test/payload.txt"));
    assert!(stat_str.contains("Size:          33 bytes"));

    // 3. Stat object with --json
    let stat_json = Command::new(velcrux_bin())
        .arg("--json")
        .arg("s3")
        .arg("stat")
        .arg("s3://test-cli-bucket/test/payload.txt")
        .output()
        .expect("execute s3 stat --json");

    assert!(stat_json.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&stat_json.stdout).unwrap();
    assert_eq!(json_val["size"], 33);

    // 4. List objects
    let ls_out = Command::new(velcrux_bin())
        .arg("s3")
        .arg("ls")
        .arg("s3://test-cli-bucket/test/")
        .output()
        .expect("execute s3 ls");

    assert!(ls_out.status.success());
    let ls_str = String::from_utf8_lossy(&ls_out.stdout);
    assert!(ls_str.contains("test/payload.txt"));

    // 5. Get object
    let get_out = Command::new(velcrux_bin())
        .arg("s3")
        .arg("get")
        .arg("s3://test-cli-bucket/test/payload.txt")
        .arg(dl_file.to_str().unwrap())
        .output()
        .expect("execute s3 get");

    assert!(get_out.status.success());
    assert_eq!(fs::read(&dl_file).unwrap(), b"Velcrux S3 Object Storage Gateway");

    // 6. Delete object
    let del_out = Command::new(velcrux_bin())
        .arg("s3")
        .arg("delete")
        .arg("s3://test-cli-bucket/test/payload.txt")
        .output()
        .expect("execute s3 delete");

    assert!(del_out.status.success());
    let del_str = String::from_utf8_lossy(&del_out.stdout);
    assert!(del_str.contains("Successfully deleted"));
}

#[test]
fn test_cli_s3_sync_bidirectional() {
    let temp = tempdir().unwrap();
    let src_dir = temp.path().join("local_dir");
    fs::create_dir_all(src_dir.join("sub")).unwrap();
    fs::write(src_dir.join("file1.bin"), b"file1-data").unwrap();
    fs::write(src_dir.join("sub/file2.bin"), b"file2-nested-data").unwrap();

    let dst_dir = temp.path().join("restored_dir");

    // 1. Upload sync via `velcrux s3 sync`
    let sync_up = Command::new(velcrux_bin())
        .arg("s3")
        .arg("sync")
        .arg(src_dir.to_str().unwrap())
        .arg("s3://sync-cli-bucket/data")
        .output()
        .expect("execute s3 sync upload");

    assert!(sync_up.status.success(), "stderr: {:?}", String::from_utf8_lossy(&sync_up.stderr));
    let sync_up_str = String::from_utf8_lossy(&sync_up.stdout);
    assert!(sync_up_str.contains("S3 Upload Sync Complete"));

    // 2. Download sync via `velcrux sync` top-level delegation
    let sync_down = Command::new(velcrux_bin())
        .arg("sync")
        .arg("s3://sync-cli-bucket/data")
        .arg(dst_dir.to_str().unwrap())
        .output()
        .expect("execute sync download");

    assert!(sync_down.status.success(), "stderr: {:?}", String::from_utf8_lossy(&sync_down.stderr));
    assert_eq!(fs::read(dst_dir.join("file1.bin")).unwrap(), b"file1-data");
    assert_eq!(fs::read(dst_dir.join("sub/file2.bin")).unwrap(), b"file2-nested-data");
}
