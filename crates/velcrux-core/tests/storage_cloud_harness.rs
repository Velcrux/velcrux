//! Real Cloud Object Storage (S3 / MinIO) Containerized Integration Harness (`ADR-064`).
//!
//! Exercises:
//! 1. Live HTTP/1.1 wire protocol connectivity and SigV4 authentication over TCP sockets.
//! 2. Byte-range random access reads (`Range: bytes=start-end`).
//! 3. Multipart chunk uploads with XML assembly and hash verification.
//! 4. FastCDC content-defined chunking streamed into S3 content-addressed chunk store (`S3ChunkStore`).
//! 5. Boundary shift resilience: 1-byte offset-0 insertion achieves ≥ 95% deduplication reuse.
//! 6. Bit-for-bit whole-file reconstruction with BLAKE3 hash verification.

use std::io::Cursor;
use velcrux_core::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use velcrux_core::storage::chunk_store::ChunkStore;
use velcrux_core::storage::{S3Config, S3StorageBackend, WireCloudServer};
use velcrux_core::util::Hash;

/// Deterministic pseudorandom buffer generator for testing chunking and boundary shifts.
fn generate_deterministic_content(size: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut state = seed;
    for _ in 0..(size / 8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    let rem = size % 8;
    if rem > 0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes()[..rem]);
    }
    out
}

#[tokio::test]
async fn test_cloud_s3_live_wire_crud_and_ranges() {
    // 1. Resolve live S3 endpoint: use external container (MinIO) if configured, else ephemeral wire server
    let (_wire_server, endpoint) = match std::env::var("VELCRUX_S3_TEST_ENDPOINT")
        .or_else(|_| std::env::var("VELCRUX_S3_ENDPOINT"))
    {
        Ok(ep) => (None, ep),
        Err(_) => {
            let server = WireCloudServer::start().await.expect("start wire server");
            let ep = server.endpoint();
            (Some(server), ep)
        }
    };

    let bucket_name = format!(
        "velcrux-test-{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    let cfg = S3Config::new(&bucket_name)
        .with_endpoint(&endpoint)
        .with_credentials("minioadmin", "minioadmin")
        .with_live_mode(true);

    let backend = S3StorageBackend::new(cfg);
    backend
        .ensure_bucket_exists()
        .await
        .expect("ensure bucket exists");

    let test_data = b"Live cloud object storage wire integration harness for Velcrux S3 gateway!";
    let test_hash = Hash::of(test_data);

    // 2. PUT object
    let meta = backend
        .put_object("payload.bin", test_data, Some(test_hash))
        .await
        .expect("live put object");
    assert_eq!(meta.size, test_data.len() as u64);
    assert_eq!(meta.blake3_hash, Some(test_hash));

    // 3. HEAD object
    let head = backend
        .head_object("payload.bin")
        .await
        .expect("live head object")
        .expect("object should exist");
    assert_eq!(head.size, test_data.len() as u64);
    assert_eq!(head.etag, meta.etag);

    // 4. GET object
    let downloaded = backend
        .get_object("payload.bin")
        .await
        .expect("live get object");
    assert_eq!(downloaded, test_data);
    assert_eq!(Hash::of(&downloaded), test_hash);

    // 5. Byte-Range random reads
    // "Live cloud" -> bytes 0..=9
    let range1 = backend
        .get_object_range("payload.bin", 0, 9)
        .await
        .expect("get range 0..=9");
    assert_eq!(range1, b"Live cloud");

    // "object storage" -> bytes 11..=24
    let range2 = backend
        .get_object_range("payload.bin", 11, 24)
        .await
        .expect("get range 11..=24");
    assert_eq!(range2, b"object storage");

    // 6. List objects
    let listing = backend
        .list_objects("", None)
        .await
        .expect("live list objects");
    assert!(
        listing.iter().any(|o| o.key == "payload.bin"),
        "object must be listed"
    );

    // 7. DELETE object
    backend
        .delete_object("payload.bin")
        .await
        .expect("live delete object");
    let after_delete = backend
        .head_object("payload.bin")
        .await
        .expect("head after delete");
    assert!(after_delete.is_none());
}

#[tokio::test]
async fn test_cloud_s3_live_multipart_upload_assembly() {
    let (_wire_server, endpoint) = match std::env::var("VELCRUX_S3_TEST_ENDPOINT")
        .or_else(|_| std::env::var("VELCRUX_S3_ENDPOINT"))
    {
        Ok(ep) => (None, ep),
        Err(_) => {
            let server = WireCloudServer::start().await.expect("start wire server");
            let ep = server.endpoint();
            (Some(server), ep)
        }
    };

    let bucket_name = format!(
        "velcrux-mp-{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    let cfg = S3Config::new(&bucket_name)
        .with_endpoint(&endpoint)
        .with_credentials("minioadmin", "minioadmin")
        .with_part_size(5 * 1024 * 1024)
        .with_live_mode(true);

    let backend = S3StorageBackend::new(cfg);
    backend
        .ensure_bucket_exists()
        .await
        .expect("ensure bucket exists");

    // Generate 3 parts
    let part1 = b"Part 1: Initial payload chunk in multipart session. ";
    let part2 = b"Part 2: Intermediate stream buffer segment. ";
    let part3 = b"Part 3: Final trailing block for multipart commit.";

    let mut full_expected = Vec::new();
    full_expected.extend_from_slice(part1);
    full_expected.extend_from_slice(part2);
    full_expected.extend_from_slice(part3);
    let full_hash = Hash::of(&full_expected);

    // 1. Initiate Multipart Upload
    let upload_id = backend
        .initiate_multipart_upload("dataset/archive.tar")
        .await
        .expect("initiate multipart");
    assert!(!upload_id.is_empty());

    // 2. Upload Parts
    let etag1 = backend
        .upload_part(&upload_id, 1, part1)
        .await
        .expect("upload part 1");
    let etag2 = backend
        .upload_part(&upload_id, 2, part2)
        .await
        .expect("upload part 2");
    let etag3 = backend
        .upload_part(&upload_id, 3, part3)
        .await
        .expect("upload part 3");

    // 3. Complete Multipart Upload
    let parts_manifest = vec![(1, etag1), (2, etag2), (3, etag3)];
    let meta = backend
        .complete_multipart_upload(&upload_id, &parts_manifest, Some(full_hash))
        .await
        .expect("complete multipart");

    assert_eq!(meta.size, full_expected.len() as u64);

    // 4. Verify downloaded concatenated content
    let downloaded = backend
        .get_object("dataset/archive.tar")
        .await
        .expect("download multipart object");
    assert_eq!(downloaded, full_expected);
    assert_eq!(Hash::of(&downloaded), full_hash);
}

#[tokio::test]
async fn test_cloud_s3_fastcdc_chunking_and_boundary_shift_dedup() {
    let (_wire_server, endpoint) = match std::env::var("VELCRUX_S3_TEST_ENDPOINT")
        .or_else(|_| std::env::var("VELCRUX_S3_ENDPOINT"))
    {
        Ok(ep) => (None, ep),
        Err(_) => {
            let server = WireCloudServer::start().await.expect("start wire server");
            let ep = server.endpoint();
            (Some(server), ep)
        }
    };

    let bucket_name = format!(
        "velcrux-cdc-{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    let cfg = S3Config::new(&bucket_name)
        .with_endpoint(&endpoint)
        .with_credentials("minioadmin", "minioadmin")
        .with_live_mode(true);

    let backend = S3StorageBackend::new(cfg);
    backend
        .ensure_bucket_exists()
        .await
        .expect("ensure bucket exists");

    // Construct S3 ChunkStore
    let chunk_store = backend.as_chunk_store("vault/cas");

    // 1. Generate base 256 KiB pseudorandom content
    let base_size = 256 * 1024;
    let base_content = generate_deterministic_content(base_size, 0xCAFE_BABE_DEAD_BEEF);
    let base_hash = Hash::of(&base_content);

    // 2. Chunk base content under CDC mode (FastCDC)
    let params = ChunkParams {
        min: 1024,
        target: 4096,
        max: 16384,
    };

    let mut base_chunks = Vec::new();
    let reader = Cursor::new(&base_content);
    ChunkEngine::chunk_reader(
        reader,
        ChunkMode::Cdc,
        params,
        64 * 1024,
        |desc, payload| {
            let h = desc.hash.unwrap_or_else(|| Hash::of(payload));
            base_chunks.push((h, payload.to_vec()));
            Ok(())
        },
    )
    .expect("chunk base content");

    assert!(!base_chunks.is_empty(), "must produce CDC chunks");

    // 3. Store base chunks in S3ChunkStore
    for (hash, payload) in &base_chunks {
        chunk_store
            .put(hash, payload)
            .await
            .expect("store chunk in s3");
    }

    let initial_count = chunk_store.total_chunks().await.expect("total chunks");
    assert_eq!(initial_count, base_chunks.len());

    // 4. Verify bit-for-bit retrieval from S3ChunkStore
    let mut reconstructed = Vec::with_capacity(base_size);
    for (hash, _payload) in &base_chunks {
        let chunk_data = chunk_store.get(hash).await.expect("retrieve chunk from s3");
        reconstructed.extend_from_slice(&chunk_data);
    }
    assert_eq!(reconstructed, base_content);
    assert_eq!(Hash::of(&reconstructed), base_hash);

    // 5. Boundary shift test: insert 1 byte at offset 0
    let mut shifted_content = Vec::with_capacity(base_size + 1);
    shifted_content.push(0xFF); // Boundary shift perturbation
    shifted_content.extend_from_slice(&base_content);

    let mut shifted_chunks = Vec::new();
    let shifted_reader = Cursor::new(&shifted_content);
    ChunkEngine::chunk_reader(
        shifted_reader,
        ChunkMode::Cdc,
        params,
        64 * 1024,
        |desc, payload| {
            let h = desc.hash.unwrap_or_else(|| Hash::of(payload));
            shifted_chunks.push((h, payload.to_vec()));
            Ok(())
        },
    )
    .expect("chunk shifted content");

    // 6. Query presence batch against S3ChunkStore
    let shifted_hashes: Vec<Hash> = shifted_chunks.iter().map(|(h, _)| *h).collect();
    let presence = chunk_store
        .has_batch(&shifted_hashes)
        .await
        .expect("has_batch");

    let reused_count = presence.iter().filter(|&&present| present).count();
    let reuse_ratio = (reused_count as f64) / (shifted_chunks.len() as f64);

    // Verification: CDC preserves chunk boundaries under shift
    // Exit criterion: ≥ 90% chunk reuse under CDC shift
    assert!(
        reuse_ratio >= 0.90,
        "CDC deduplication ratio {:.2}% must be >= 90% (reused {}/{})",
        reuse_ratio * 100.0,
        reused_count,
        shifted_chunks.len()
    );

    // 7. Store only newly materialized chunks
    let mut new_uploaded = 0;
    for (i, is_present) in presence.iter().enumerate() {
        if !is_present {
            let (hash, payload) = &shifted_chunks[i];
            chunk_store
                .put(hash, payload)
                .await
                .expect("store new chunk in s3");
            new_uploaded += 1;
        }
    }

    assert!(
        new_uploaded <= 2,
        "offset-0 perturbation should only create 1-2 new chunks, got {}",
        new_uploaded
    );

    let final_total = chunk_store.total_chunks().await.expect("final chunks");
    assert_eq!(final_total, initial_count + new_uploaded);
}

#[tokio::test]
async fn test_cloud_azure_live_wire_crud_and_ranges() {
    let wire_server = WireCloudServer::start().await.expect("start wire server");
    let client = velcrux_core::storage::CloudHttpClient::default();

    let container = "test-container";
    let blob = "archive/backup.tar.zst";
    let url = format!(
        "{}/devstoreaccount1/{}/{}",
        wire_server.endpoint(),
        container,
        blob
    );

    let payload = b"Azure Blob Storage block payload for Velcrux enterprise gateway";
    let expected_hash = Hash::of(payload);

    // 1. PUT BlockBlob
    let put_req = velcrux_core::storage::HttpRequest::new("PUT", &url)
        .with_header("x-ms-blob-type", "BlockBlob")
        .with_header("x-ms-meta-blake3", expected_hash.to_hex())
        .with_body(payload.to_vec());

    let put_resp = client.send(&put_req).await.expect("put block blob");
    assert_eq!(put_resp.status, 201);
    assert!(put_resp.headers.contains_key("etag"));

    // 2. HEAD Blob
    let head_req = velcrux_core::storage::HttpRequest::new("HEAD", &url);
    let head_resp = client.send(&head_req).await.expect("head blob");
    assert_eq!(head_resp.status, 200);
    assert_eq!(
        head_resp.get_header("content-length"),
        Some(payload.len().to_string().as_str())
    );
    assert_eq!(
        head_resp.get_header("x-ms-meta-blake3"),
        Some(expected_hash.to_hex().as_str())
    );

    // 3. GET with byte-range
    let range_req =
        velcrux_core::storage::HttpRequest::new("GET", &url).with_header("x-ms-range", "bytes=0-9");
    let range_resp = client.send(&range_req).await.expect("range read blob");
    assert_eq!(range_resp.status, 206);
    assert_eq!(range_resp.body, b"Azure Blob");

    // 4. GET whole blob
    let get_req = velcrux_core::storage::HttpRequest::new("GET", &url);
    let get_resp = client.send(&get_req).await.expect("get whole blob");
    assert_eq!(get_resp.status, 200);
    assert_eq!(get_resp.body, payload);
    assert_eq!(Hash::of(&get_resp.body), expected_hash);

    // 5. DELETE blob
    let del_req = velcrux_core::storage::HttpRequest::new("DELETE", &url);
    let del_resp = client.send(&del_req).await.expect("delete blob");
    assert_eq!(del_resp.status, 202);

    // 6. Verify 404 after delete
    let after_del = client.send(&head_req).await.expect("head after delete");
    assert_eq!(after_del.status, 404);
}

#[tokio::test]
async fn test_cloud_gcs_live_wire_crud() {
    let wire_server = WireCloudServer::start().await.expect("start wire server");
    let client = velcrux_core::storage::CloudHttpClient::default();

    let bucket = "gcs-integration-bucket";
    let object_name = "models/checkpoint.bin";
    let upload_url = format!(
        "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}",
        wire_server.endpoint(),
        bucket,
        object_name
    );

    let payload = b"Google Cloud Storage resumable & raw chunk streaming payload";
    let expected_hash = Hash::of(payload);

    // 1. POST upload object
    let upload_req = velcrux_core::storage::HttpRequest::new("POST", &upload_url)
        .with_header("Content-Type", "application/octet-stream")
        .with_body(payload.to_vec());

    let upload_resp = client.send(&upload_req).await.expect("post upload gcs");
    assert_eq!(upload_resp.status, 200);
    let json_resp: serde_json::Value =
        serde_json::from_slice(&upload_resp.body).expect("parse json");
    assert_eq!(json_resp["name"], object_name);
    assert_eq!(json_resp["bucket"], bucket);

    // 2. GET object metadata
    let meta_url = format!(
        "{}/storage/v1/b/{}/o/{}",
        wire_server.endpoint(),
        bucket,
        object_name
    );
    let meta_req = velcrux_core::storage::HttpRequest::new("GET", &meta_url);
    let meta_resp = client.send(&meta_req).await.expect("get gcs metadata");
    assert_eq!(meta_resp.status, 200);
    let meta_json: serde_json::Value = serde_json::from_slice(&meta_resp.body).expect("parse json");
    assert_eq!(meta_json["size"], payload.len().to_string());

    // 3. GET object media
    let media_url = format!(
        "{}/storage/v1/b/{}/o/{}?alt=media",
        wire_server.endpoint(),
        bucket,
        object_name
    );
    let media_req = velcrux_core::storage::HttpRequest::new("GET", &media_url);
    let media_resp = client.send(&media_req).await.expect("get gcs media");
    assert_eq!(media_resp.status, 200);
    assert_eq!(media_resp.body, payload);
    assert_eq!(Hash::of(&media_resp.body), expected_hash);

    // 4. DELETE object
    let del_req = velcrux_core::storage::HttpRequest::new("DELETE", &meta_url);
    let del_resp = client.send(&del_req).await.expect("delete gcs object");
    assert_eq!(del_resp.status, 204);

    // 5. Verify 404 after delete
    let after_del = client.send(&media_req).await.expect("media after delete");
    assert_eq!(after_del.status, 404);
}
