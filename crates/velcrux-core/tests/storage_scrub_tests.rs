//! Unit and integration tests for Data Integrity Scrubbing & Bit-Rot Repair Daemon (Option BF).

use std::fs;
use tempfile::tempdir;
use velcrux_core::storage::chunk_store::{ChunkStore, LocalChunkStore};
use velcrux_core::storage::scrub::{
    ChunkIntegrityStatus, DataScrubber, ScrubMode, ScrubOptions,
};
use velcrux_core::util::Hash;

#[tokio::test]
async fn test_scrub_healthy_chunk_store() {
    let tmp = tempdir().unwrap();
    let store = LocalChunkStore::new(tmp.path()).await.unwrap();

    // Ingest 10 chunks
    for i in 0..10 {
        let data = format!("Healthy chunk payload content {}", i);
        let hash = Hash::of(data.as_bytes());
        store.put(&hash, data.as_bytes()).await.unwrap();
    }

    let options = ScrubOptions {
        mode: ScrubMode::VerifyOnly,
        rate_limit_bytes_per_sec: None,
        quarantine_dir: None,
    };

    let report = DataScrubber::scrub_local_store(&store, &options)
        .await
        .expect("scrub run");

    assert_eq!(report.scanned_chunks, 10);
    assert_eq!(report.healthy_chunks, 10);
    assert_eq!(report.corrupted_chunks, 0);
    assert_eq!(report.repaired_chunks, 0);
    assert!(report.scanned_bytes > 0);
    assert!(report.findings.is_empty());
}

#[tokio::test]
async fn test_scrub_bit_rot_detection_verify_only() {
    let tmp = tempdir().unwrap();
    let store = LocalChunkStore::new(tmp.path()).await.unwrap();

    let mut hashes = Vec::new();
    for i in 0..5 {
        let data = format!("Test bit-rot chunk payload {}", i);
        let hash = Hash::of(data.as_bytes());
        store.put(&hash, data.as_bytes()).await.unwrap();
        hashes.push(hash);
    }

    // Corrupt chunk 1 (flip byte)
    let p1 = store.chunk_path(&hashes[1]);
    fs::write(&p1, b"Corrupted silent bit rot data!").unwrap();

    // Truncate chunk 3 (0 bytes)
    let p3 = store.chunk_path(&hashes[3]);
    fs::write(&p3, b"").unwrap();

    let options = ScrubOptions {
        mode: ScrubMode::VerifyOnly,
        rate_limit_bytes_per_sec: None,
        quarantine_dir: None,
    };

    let report = DataScrubber::scrub_local_store(&store, &options)
        .await
        .expect("scrub run");

    assert_eq!(report.scanned_chunks, 5);
    assert_eq!(report.healthy_chunks, 3);
    assert_eq!(report.corrupted_chunks, 2);
    assert_eq!(report.findings.len(), 2);

    let status1 = report
        .findings
        .iter()
        .find(|f| f.chunk_hash == hashes[1].to_string())
        .map(|f| f.status);
    assert_eq!(status1, Some(ChunkIntegrityStatus::BitRotCorrupted));

    let status3 = report
        .findings
        .iter()
        .find(|f| f.chunk_hash == hashes[3].to_string())
        .map(|f| f.status);
    assert_eq!(status3, Some(ChunkIntegrityStatus::Truncated));

    // Verify files remain in place in VerifyOnly mode
    assert!(p1.exists());
    assert!(p3.exists());
}

#[tokio::test]
async fn test_scrub_quarantine_mode() {
    let tmp = tempdir().unwrap();
    let store = LocalChunkStore::new(tmp.path()).await.unwrap();

    let mut hashes = Vec::new();
    for i in 0..5 {
        let data = format!("Quarantine test chunk payload {}", i);
        let hash = Hash::of(data.as_bytes());
        store.put(&hash, data.as_bytes()).await.unwrap();
        hashes.push(hash);
    }

    // Corrupt chunk 2
    let p2 = store.chunk_path(&hashes[2]);
    fs::write(&p2, b"Corrupted chunk data 2").unwrap();

    let quarantine_dir = tmp.path().join("quarantine_hold");
    let options = ScrubOptions {
        mode: ScrubMode::Quarantine,
        rate_limit_bytes_per_sec: None,
        quarantine_dir: Some(quarantine_dir.clone()),
    };

    let report = DataScrubber::scrub_local_store(&store, &options)
        .await
        .expect("scrub run");

    assert_eq!(report.scanned_chunks, 5);
    assert_eq!(report.healthy_chunks, 4);
    assert_eq!(report.corrupted_chunks, 1);
    assert_eq!(report.quarantined_chunks, 1);

    // Corrupted chunk must have been moved from original path to quarantine dir
    assert!(!p2.exists());
    let quarantined_file = quarantine_dir.join(format!("{}.corrupt", hashes[2]));
    assert!(quarantined_file.exists());
}

#[tokio::test]
async fn test_scrub_self_healing_from_peer() {
    let tmp = tempdir().unwrap();
    let local_dir = tmp.path().join("local_store");
    let peer_dir = tmp.path().join("peer_store");

    let local_store = LocalChunkStore::new(&local_dir).await.unwrap();
    let peer_store = LocalChunkStore::new(&peer_dir).await.unwrap();

    // Populate both stores with identical chunks
    let mut hashes = Vec::new();
    for i in 0..5 {
        let data = format!("Replicated chunk payload {}", i);
        let hash = Hash::of(data.as_bytes());
        local_store.put(&hash, data.as_bytes()).await.unwrap();
        peer_store.put(&hash, data.as_bytes()).await.unwrap();
        hashes.push(hash);
    }

    // Corrupt chunk 0 and chunk 4 on the local store
    let p0 = local_store.chunk_path(&hashes[0]);
    let p4 = local_store.chunk_path(&hashes[4]);
    fs::write(&p0, b"Bit rot corrupted payload 0").unwrap();
    fs::write(&p4, b"Bit rot corrupted payload 4").unwrap();

    let options = ScrubOptions {
        mode: ScrubMode::HealFromPeer,
        rate_limit_bytes_per_sec: None,
        quarantine_dir: None,
    };

    let report = DataScrubber::scrub_and_heal(&local_store, &peer_store, &options)
        .await
        .expect("scrub and heal");

    assert_eq!(report.scanned_chunks, 5);
    assert_eq!(report.healthy_chunks, 3);
    assert_eq!(report.corrupted_chunks, 2);
    assert_eq!(report.repaired_chunks, 2);
    assert!(report.repaired_bytes > 0);

    // Now re-scrub in VerifyOnly mode: all 5 chunks must be healthy
    let verify_options = ScrubOptions {
        mode: ScrubMode::VerifyOnly,
        rate_limit_bytes_per_sec: None,
        quarantine_dir: None,
    };
    let post_report = DataScrubber::scrub_local_store(&local_store, &verify_options)
        .await
        .expect("verify scrub");
    assert_eq!(post_report.scanned_chunks, 5);
    assert_eq!(post_report.healthy_chunks, 5);
    assert_eq!(post_report.corrupted_chunks, 0);
}

#[tokio::test]
async fn test_scrub_report_save_and_load() {
    let tmp = tempdir().unwrap();
    let store = LocalChunkStore::new(tmp.path()).await.unwrap();
    let report_file = tmp.path().join("scrub_report.json");

    let data = b"Test single chunk for report check";
    let hash = Hash::of(data);
    store.put(&hash, data).await.unwrap();

    let options = ScrubOptions::default();
    let report = DataScrubber::scrub_local_store(&store, &options).await.unwrap();

    DataScrubber::save_report(&report, &report_file).unwrap();
    assert!(report_file.exists());

    let loaded = DataScrubber::load_latest_report(&report_file).unwrap().expect("must exist");
    assert_eq!(loaded.scanned_chunks, 1);
    assert_eq!(loaded.healthy_chunks, 1);
    assert_eq!(loaded.target_path, store.root().display().to_string());
}
