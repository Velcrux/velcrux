use std::collections::BTreeMap;
use tempfile::tempdir;
use velcrux_core::storage::{S3Config, S3Error, S3StorageBackend, SigV4Signer};
use velcrux_core::util::Hash;

#[test]
fn test_s3_sigv4_signing_canonical_format() {
    let signer = SigV4Signer::new(
        "us-west-2",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );

    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "mybucket.s3.us-west-2.amazonaws.com".to_string());
    headers.insert("x-amz-date".to_string(), "20261012T120000Z".to_string());
    headers.insert("x-amz-content-sha256".to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string());

    let (auth_header, date_header) = signer.sign_request(
        "GET",
        "/test/object.tar.zst",
        "prefix=test&delimiter=%2F",
        &headers,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "20261012T120000Z",
    );

    assert_eq!(date_header, "20261012T120000Z");
    assert!(auth_header.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261012/us-west-2/s3/aws4_request"));
    assert!(auth_header.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    assert!(auth_header.contains("Signature="));
}

#[tokio::test]
async fn test_s3_backend_object_lifecycle_and_ranges() {
    let cfg = S3Config::new("cloud-dataset").with_prefix("v1/raw");
    let backend = S3StorageBackend::new(cfg);

    let payload = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let hash = Hash::of(payload);

    // 1. Put object
    let meta = backend.put_object("alphabet.dat", payload, Some(hash)).await.unwrap();
    assert_eq!(meta.size, payload.len() as u64);
    assert_eq!(meta.key, "v1/raw/alphabet.dat");
    assert_eq!(meta.blake3_hash, Some(hash));

    // 2. Head object
    let head = backend.head_object("alphabet.dat").await.unwrap().expect("head exists");
    assert_eq!(head.size, payload.len() as u64);
    assert_eq!(head.etag, meta.etag);

    // 3. Range reads
    // Read first 10 bytes: '0123456789'
    let range1 = backend.get_object_range("alphabet.dat", 0, 9).await.unwrap();
    assert_eq!(range1, b"0123456789");

    // Read middle bytes 10-15: 'abcdef'
    let range2 = backend.get_object_range("alphabet.dat", 10, 15).await.unwrap();
    assert_eq!(range2, b"abcdef");

    // Read trailing bytes beyond EOF
    let range_beyond = backend.get_object_range("alphabet.dat", 60, 100).await.unwrap();
    assert_eq!(range_beyond, b"YZ");

    // 4. List objects
    let listing = backend.list_objects("v1/raw", None).await.unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].key, "v1/raw/alphabet.dat");

    // 5. Delete object
    backend.delete_object("alphabet.dat").await.unwrap();
    assert!(backend.head_object("alphabet.dat").await.unwrap().is_none());

    // 6. 404 error
    let err = backend.get_object("alphabet.dat").await.unwrap_err();
    assert!(matches!(err, S3Error::NotFound { .. }));
}

#[tokio::test]
async fn test_s3_backend_multipart_assembly() {
    let mut cfg = S3Config::new("mp-dataset");
    cfg.part_size_bytes = 256;
    let backend = S3StorageBackend::new(cfg);

    // Generate 1024 bytes (4 parts of 256 bytes)
    let payload = vec![77u8; 1024];
    let hash = Hash::of(&payload);

    let meta = backend.put_object_multipart("chunked.bin", &payload, Some(hash)).await.unwrap();
    assert_eq!(meta.size, 1024);
    assert!(meta.etag.contains("-4\""));

    let downloaded = backend.get_object("chunked.bin").await.unwrap();
    assert_eq!(downloaded, payload);
    assert_eq!(Hash::of(&downloaded), hash);
}

#[tokio::test]
async fn test_s3_backend_bidirectional_sync() {
    let local_src = tempdir().unwrap();
    let src_path = local_src.path();

    std::fs::write(src_path.join("file_a.txt"), b"File A content").unwrap();
    std::fs::create_dir_all(src_path.join("nested/dir")).unwrap();
    std::fs::write(src_path.join("nested/dir/file_b.txt"), b"File B nested content").unwrap();

    let cfg = S3Config::new("sync-test-bucket").with_prefix("mirrors/site1");
    let backend = S3StorageBackend::new(cfg);

    // 1. Initial upload sync
    let up_report = backend.sync_from_local(src_path, "mirrors/site1").await.unwrap();
    assert_eq!(up_report.total_objects, 2);
    assert_eq!(up_report.objects_transferred, 2);
    assert_eq!(up_report.objects_unchanged, 0);

    // 2. Second upload sync (idempotent / no-op)
    let up_report2 = backend.sync_from_local(src_path, "mirrors/site1").await.unwrap();
    assert_eq!(up_report2.total_objects, 2);
    assert_eq!(up_report2.objects_transferred, 0);
    assert_eq!(up_report2.objects_unchanged, 2);

    // 3. Download sync to empty local directory
    let local_dst = tempdir().unwrap();
    let dst_path = local_dst.path();

    let down_report = backend.sync_to_local("mirrors/site1", dst_path).await.unwrap();
    assert_eq!(down_report.total_objects, 2);
    assert_eq!(down_report.objects_transferred, 2);

    assert_eq!(std::fs::read(dst_path.join("file_a.txt")).unwrap(), b"File A content");
    assert_eq!(std::fs::read(dst_path.join("nested/dir/file_b.txt")).unwrap(), b"File B nested content");
}
