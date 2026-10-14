//! Integration tests for Multi-Cloud CLI commands (GCS and Azure Blob) (Option BK).

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
fn test_cli_gcs_put_stat_ls_get_delete() {
    let temp = tempdir().unwrap();
    let local_file = temp.path().join("gcs_payload.txt");
    fs::write(&local_file, b"Velcrux Google Cloud Storage Gateway").unwrap();

    let dl_file = temp.path().join("downloaded_gcs.txt");

    // 1. Put object
    let put_out = Command::new(velcrux_bin())
        .arg("gcs")
        .arg("put")
        .arg(local_file.to_str().unwrap())
        .arg("gs://test-gcs-cli/test/payload.txt")
        .output()
        .expect("execute gcs put");

    assert!(
        put_out.status.success(),
        "gcs put failed: {:?}",
        String::from_utf8_lossy(&put_out.stderr)
    );
    let put_str = String::from_utf8_lossy(&put_out.stdout);
    assert!(put_str.contains("Successfully uploaded"));

    // 2. Stat object
    let stat_out = Command::new(velcrux_bin())
        .arg("gcs")
        .arg("stat")
        .arg("gs://test-gcs-cli/test/payload.txt")
        .output()
        .expect("execute gcs stat");

    assert!(stat_out.status.success());
    let stat_str = String::from_utf8_lossy(&stat_out.stdout);
    assert!(stat_str.contains("GCS Object Metadata: gs://test-gcs-cli/test/payload.txt"));
    assert!(stat_str.contains("Size:          36 bytes"));

    // 3. Stat object with --json
    let stat_json = Command::new(velcrux_bin())
        .arg("--json")
        .arg("gcs")
        .arg("stat")
        .arg("gs://test-gcs-cli/test/payload.txt")
        .output()
        .expect("execute gcs stat --json");

    assert!(stat_json.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&stat_json.stdout).unwrap();
    assert_eq!(json_val["size"], 36);

    // 4. List objects
    let ls_out = Command::new(velcrux_bin())
        .arg("gcs")
        .arg("ls")
        .arg("gs://test-gcs-cli/test/")
        .output()
        .expect("execute gcs ls");

    assert!(ls_out.status.success());
    let ls_str = String::from_utf8_lossy(&ls_out.stdout);
    assert!(ls_str.contains("test/payload.txt"));

    // 5. Get object
    let get_out = Command::new(velcrux_bin())
        .arg("gcs")
        .arg("get")
        .arg("gs://test-gcs-cli/test/payload.txt")
        .arg(dl_file.to_str().unwrap())
        .output()
        .expect("execute gcs get");

    assert!(get_out.status.success());
    assert_eq!(
        fs::read(&dl_file).unwrap(),
        b"Velcrux Google Cloud Storage Gateway"
    );

    // 6. Delete object
    let del_out = Command::new(velcrux_bin())
        .arg("gcs")
        .arg("delete")
        .arg("gs://test-gcs-cli/test/payload.txt")
        .output()
        .expect("execute gcs delete");

    assert!(del_out.status.success());
    let del_str = String::from_utf8_lossy(&del_out.stdout);
    assert!(del_str.contains("Successfully deleted"));
}

#[test]
fn test_cli_azure_put_stat_ls_get_delete() {
    let temp = tempdir().unwrap();
    let local_file = temp.path().join("azure_payload.txt");
    fs::write(&local_file, b"Velcrux Azure Blob Storage Gateway").unwrap();

    let dl_file = temp.path().join("downloaded_azure.txt");

    // 1. Put blob
    let put_out = Command::new(velcrux_bin())
        .arg("azure")
        .arg("put")
        .arg(local_file.to_str().unwrap())
        .arg("az://test-azure-cli/test/payload.txt")
        .output()
        .expect("execute azure put");

    assert!(
        put_out.status.success(),
        "azure put failed: {:?}",
        String::from_utf8_lossy(&put_out.stderr)
    );
    let put_str = String::from_utf8_lossy(&put_out.stdout);
    assert!(put_str.contains("Successfully uploaded"));

    // 2. Stat blob
    let stat_out = Command::new(velcrux_bin())
        .arg("azure")
        .arg("stat")
        .arg("az://test-azure-cli/test/payload.txt")
        .output()
        .expect("execute azure stat");

    assert!(stat_out.status.success());
    let stat_str = String::from_utf8_lossy(&stat_out.stdout);
    assert!(stat_str.contains("Azure Blob Properties: az://test-azure-cli/test/payload.txt"));
    assert!(stat_str.contains("Size:          34 bytes"));

    // 3. Stat blob with --json
    let stat_json = Command::new(velcrux_bin())
        .arg("--json")
        .arg("azure")
        .arg("stat")
        .arg("az://test-azure-cli/test/payload.txt")
        .output()
        .expect("execute azure stat --json");

    assert!(stat_json.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&stat_json.stdout).unwrap();
    assert_eq!(json_val["size"], 34);

    // 4. List blobs
    let ls_out = Command::new(velcrux_bin())
        .arg("azure")
        .arg("ls")
        .arg("az://test-azure-cli/test/")
        .output()
        .expect("execute azure ls");

    assert!(ls_out.status.success());
    let ls_str = String::from_utf8_lossy(&ls_out.stdout);
    assert!(ls_str.contains("test/payload.txt"));

    // 5. Get blob
    let get_out = Command::new(velcrux_bin())
        .arg("azure")
        .arg("get")
        .arg("az://test-azure-cli/test/payload.txt")
        .arg(dl_file.to_str().unwrap())
        .output()
        .expect("execute azure get");

    assert!(get_out.status.success());
    assert_eq!(
        fs::read(&dl_file).unwrap(),
        b"Velcrux Azure Blob Storage Gateway"
    );

    // 6. Delete blob
    let del_out = Command::new(velcrux_bin())
        .arg("azure")
        .arg("delete")
        .arg("az://test-azure-cli/test/payload.txt")
        .output()
        .expect("execute azure delete");

    assert!(del_out.status.success());
    let del_str = String::from_utf8_lossy(&del_out.stdout);
    assert!(del_str.contains("Successfully deleted"));
}

#[test]
fn test_cli_multicloud_upload_download_url_routing() {
    let temp = tempdir().unwrap();
    let local_file = temp.path().join("cloud_url_payload.txt");
    fs::write(&local_file, b"Routing via generic upload and download").unwrap();

    let dl_file = temp.path().join("dl_generic.txt");

    // 1. Generic upload with gs:// URL
    let up_gcs = Command::new(velcrux_bin())
        .arg("upload")
        .arg(local_file.to_str().unwrap())
        .arg("gs://url-routing-bucket/generic/file.dat")
        .output()
        .expect("execute upload gs://");
    assert!(up_gcs.status.success());

    // 2. Generic download with gs:// URL
    let down_gcs = Command::new(velcrux_bin())
        .arg("download")
        .arg("gs://url-routing-bucket/generic/file.dat")
        .arg(dl_file.to_str().unwrap())
        .output()
        .expect("execute download gs://");
    assert!(down_gcs.status.success());
    assert_eq!(
        fs::read(&dl_file).unwrap(),
        b"Routing via generic upload and download"
    );

    // 3. Generic upload with az:// URL
    let up_az = Command::new(velcrux_bin())
        .arg("upload")
        .arg(local_file.to_str().unwrap())
        .arg("az://url-routing-container/generic/blob.dat")
        .output()
        .expect("execute upload az://");
    assert!(up_az.status.success());

    // 4. Generic download with az:// URL
    let dl_az_file = temp.path().join("dl_az.txt");
    let down_az = Command::new(velcrux_bin())
        .arg("download")
        .arg("az://url-routing-container/generic/blob.dat")
        .arg(dl_az_file.to_str().unwrap())
        .output()
        .expect("execute download az://");
    assert!(down_az.status.success());
    assert_eq!(
        fs::read(&dl_az_file).unwrap(),
        b"Routing via generic upload and download"
    );
}
