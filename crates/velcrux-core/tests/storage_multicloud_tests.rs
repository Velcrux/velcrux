//! Integration tests for Multi-Cloud Object Storage Backends: GCS & Azure Blob (Option BK).

use std::fs;
use tempfile::tempdir;
use velcrux_core::storage::{
    AzureBlobConfig, AzureBlobStorageBackend, AzureSharedKeySigner, GcsConfig, GcsStorageBackend,
    StorageBackend, VPath,
};
use velcrux_core::util::Hash;

#[tokio::test]
async fn test_gcs_full_lifecycle_and_chunked_upload() {
    let mut cfg = GcsConfig::new("integration-gcs-bucket");
    cfg.chunk_size_bytes = 32; // Forces chunked resumable upload
    let backend = GcsStorageBackend::new(cfg);

    let test_data = b"Multi-cloud Google Cloud Storage provider with resumable chunked streaming!";
    let hash = Hash::of(test_data);

    // 1. Put object via resumable upload
    let meta = backend
        .put_object_resumable("datasets/2026/sample.bin", test_data, Some(hash))
        .await
        .expect("gcs put_object_resumable");

    assert_eq!(meta.size, test_data.len() as u64);
    assert_eq!(meta.blake3_hash, Some(hash));
    assert!(meta.generation > 0);

    // 2. Head / stat
    let stat = backend
        .head_object("datasets/2026/sample.bin")
        .await
        .expect("head_object")
        .expect("object should exist");
    assert_eq!(stat.size, test_data.len() as u64);
    assert_eq!(stat.blake3_hash, Some(hash));

    // 3. Range read
    let slice = backend
        .get_object_range("datasets/2026/sample.bin", 12, 23)
        .await
        .expect("range read");
    assert_eq!(slice, b"Google Cloud");

    // 4. List objects
    let list = backend
        .list_objects("datasets/", None)
        .await
        .expect("list_objects");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "datasets/2026/sample.bin");

    // 5. StorageBackend trait verification
    let vpath = VPath::validate("datasets/2026/sample.bin").unwrap();
    let trait_stat = backend
        .stat(&vpath)
        .await
        .expect("trait stat")
        .expect("stat present");
    assert_eq!(trait_stat.size, test_data.len() as u64);

    let mut reader = backend.open_read(&vpath).await.expect("open_read");
    let mut buf = [0u8; 11];
    let n = reader.read_at(0, &mut buf).await.expect("read_at");
    assert_eq!(n, 11);
    assert_eq!(&buf, b"Multi-cloud");

    // 6. Delete
    backend
        .delete_object("datasets/2026/sample.bin")
        .await
        .expect("delete");
    let after_stat = backend
        .head_object("datasets/2026/sample.bin")
        .await
        .expect("head after delete");
    assert!(after_stat.is_none());
}

#[tokio::test]
async fn test_gcs_bidirectional_sync_verification() {
    let temp = tempdir().unwrap();
    let local_src = temp.path().join("local_src");
    let local_dst = temp.path().join("local_dst");
    fs::create_dir_all(local_src.join("nested")).unwrap();

    fs::write(local_src.join("alpha.txt"), b"Alpha payload content").unwrap();
    fs::write(
        local_src.join("nested/beta.txt"),
        b"Beta nested payload content",
    )
    .unwrap();

    let cfg = GcsConfig::new("sync-gcs-verify");
    let backend = GcsStorageBackend::new(cfg);

    // Sync upload
    let report_up = backend
        .sync_from_local(&local_src, "cloud/prefix")
        .await
        .expect("sync upload");
    assert_eq!(report_up.total_objects, 2);
    assert_eq!(report_up.objects_transferred, 2);

    // Idempotent second sync (no objects transferred)
    let report_up2 = backend
        .sync_from_local(&local_src, "cloud/prefix")
        .await
        .expect("sync upload 2");
    assert_eq!(report_up2.total_objects, 2);
    assert_eq!(report_up2.objects_transferred, 0);
    assert_eq!(report_up2.objects_unchanged, 2);

    // Sync download
    let report_down = backend
        .sync_to_local("cloud/prefix", &local_dst)
        .await
        .expect("sync download");
    assert_eq!(report_down.total_objects, 2);
    assert_eq!(report_down.objects_transferred, 2);

    assert_eq!(
        fs::read(local_dst.join("alpha.txt")).unwrap(),
        b"Alpha payload content"
    );
    assert_eq!(
        fs::read(local_dst.join("nested/beta.txt")).unwrap(),
        b"Beta nested payload content"
    );
}

#[tokio::test]
async fn test_azure_full_lifecycle_and_block_blob_commit() {
    let mut cfg = AzureBlobConfig::new("integration-az-container");
    cfg.block_size_bytes = 24; // Forces multi-block commit
    let backend = AzureBlobStorageBackend::new(cfg);

    let test_data = b"Multi-cloud Azure Blob Storage provider with Put Block and Put Block List!";
    let hash = Hash::of(test_data);

    // 1. Put block blob with chunked blocks
    let meta = backend
        .put_blob_blocks("archives/logs.tar", test_data, Some(hash))
        .await
        .expect("azure put_blob_blocks");

    assert_eq!(meta.size, test_data.len() as u64);
    assert_eq!(meta.blake3_hash, Some(hash));

    // 2. Get properties
    let props = backend
        .get_blob_properties("archives/logs.tar")
        .await
        .expect("get_blob_properties")
        .expect("blob should exist");
    assert_eq!(props.size, test_data.len() as u64);
    assert_eq!(props.blake3_hash, Some(hash));

    // 3. Range read
    let slice = backend
        .get_blob_range("archives/logs.tar", 12, 21)
        .await
        .expect("range read");
    assert_eq!(slice, b"Azure Blob");

    // 4. List blobs
    let list = backend
        .list_blobs("archives/", None)
        .await
        .expect("list_blobs");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "archives/logs.tar");

    // 5. StorageBackend trait verification
    let vpath = VPath::validate("archives/logs.tar").unwrap();
    let trait_stat = backend
        .stat(&vpath)
        .await
        .expect("trait stat")
        .expect("stat present");
    assert_eq!(trait_stat.size, test_data.len() as u64);

    let mut reader = backend.open_read(&vpath).await.expect("open_read");
    let mut buf = [0u8; 11];
    let n = reader.read_at(0, &mut buf).await.expect("read_at");
    assert_eq!(n, 11);
    assert_eq!(&buf, b"Multi-cloud");

    // 6. Delete
    backend
        .delete_blob("archives/logs.tar")
        .await
        .expect("delete");
    let after_stat = backend
        .get_blob_properties("archives/logs.tar")
        .await
        .expect("props after delete");
    assert!(after_stat.is_none());
}

#[tokio::test]
async fn test_azure_bidirectional_sync_verification() {
    let temp = tempdir().unwrap();
    let local_src = temp.path().join("local_src");
    let local_dst = temp.path().join("local_dst");
    fs::create_dir_all(local_src.join("subfolder")).unwrap();

    fs::write(local_src.join("doc1.pdf"), b"PDF document payload").unwrap();
    fs::write(
        local_src.join("subfolder/doc2.pdf"),
        b"Second PDF nested payload",
    )
    .unwrap();

    let cfg = AzureBlobConfig::new("sync-az-verify");
    let backend = AzureBlobStorageBackend::new(cfg);

    // Sync upload
    let report_up = backend
        .sync_from_local(&local_src, "container/prefix")
        .await
        .expect("sync upload");
    assert_eq!(report_up.total_objects, 2);
    assert_eq!(report_up.objects_transferred, 2);

    // Idempotent second sync (no objects transferred)
    let report_up2 = backend
        .sync_from_local(&local_src, "container/prefix")
        .await
        .expect("sync upload 2");
    assert_eq!(report_up2.total_objects, 2);
    assert_eq!(report_up2.objects_transferred, 0);
    assert_eq!(report_up2.objects_unchanged, 2);

    // Sync download
    let report_down = backend
        .sync_to_local("container/prefix", &local_dst)
        .await
        .expect("sync download");
    assert_eq!(report_down.total_objects, 2);
    assert_eq!(report_down.objects_transferred, 2);

    assert_eq!(
        fs::read(local_dst.join("doc1.pdf")).unwrap(),
        b"PDF document payload"
    );
    assert_eq!(
        fs::read(local_dst.join("subfolder/doc2.pdf")).unwrap(),
        b"Second PDF nested payload"
    );
}

#[test]
fn test_azure_shared_key_signing_and_url_variations() {
    let (c1, p1) =
        AzureBlobConfig::parse_azure_url("az://container-one/my/deep/path.tar.gz").unwrap();
    assert_eq!(c1, "container-one");
    assert_eq!(p1, "my/deep/path.tar.gz");

    let (c2, p2) =
        AzureBlobConfig::parse_azure_url("azure://backup-vault/snapshot-2026.iso").unwrap();
    assert_eq!(c2, "backup-vault");
    assert_eq!(p2, "snapshot-2026.iso");

    let (c3, p3) = AzureBlobConfig::parse_azure_url(
        "https://myaccount.blob.core.windows.net/prod-assets/images/logo.png",
    )
    .unwrap();
    assert_eq!(c3, "prod-assets");
    assert_eq!(p3, "images/logo.png");

    let _dummy_secret = b"12345678901234567890123456789012";
    let encoded_key = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
    let signer = AzureSharedKeySigner::new("testacc", encoded_key).unwrap();

    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "x-ms-date".to_string(),
        "Wed, 14 Oct 2026 12:00:00 GMT".to_string(),
    );
    headers.insert("x-ms-version".to_string(), "2023-11-03".to_string());
    let query = std::collections::BTreeMap::new();

    let auth = signer.sign_request("GET", "/prod-assets/images/logo.png", &headers, &query);
    assert!(auth.starts_with("SharedKey testacc:"));
}
