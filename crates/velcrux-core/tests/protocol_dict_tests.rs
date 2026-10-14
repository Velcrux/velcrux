//! Unit and integration tests for Zstandard pre-trained dictionary learning engine (Option BE).

use std::fs;
use tempfile::tempdir;
use velcrux_core::protocol::compression::DEFAULT_ZSTD_LEVEL;
use velcrux_core::protocol::dict::{
    compress_with_dict, decompress_with_dict_bounded, evaluate_dictionary_ratio, DictionaryCatalog,
    DictionaryTrainer,
};

fn generate_synthetic_json_samples(count: usize) -> Vec<Vec<u8>> {
    let mut samples = Vec::with_capacity(count);
    for i in 0..count {
        let json = format!(
            r#"{{"event":"audit_log","index":{},"service":"velcrux-transfer-daemon","host":"node-{}.cluster.local","timestamp":1791800000,"severity":"INFO","metadata":{{"user_id":"usr_{:04x}","action":"chunk_sync","status":"SUCCESS","latency_ms":12.4}},"message":"Successfully synced chunk {} with peer cluster node"}}"#,
            i,
            i % 10,
            i * 7,
            i
        );
        samples.push(json.into_bytes());
    }
    samples
}

#[test]
fn test_dict_trainer_from_samples_and_compression_roundtrip() {
    let samples = generate_synthetic_json_samples(50);
    let now = 1791805000;

    // Train dictionary with 32 KiB cap
    let dict = DictionaryTrainer::train_from_samples(
        &samples,
        32 * 1024,
        "json-telemetry",
        "Trained telemetry dictionary for audit log events",
        now,
    )
    .expect("train dictionary");

    assert_eq!(dict.name(), "json-telemetry");
    assert!(dict.dict_id() > 0);
    assert!(!dict.bytes().is_empty());
    assert_eq!(dict.metadata.sample_count, 50);

    // Test compression on a sample payload
    let test_payload = generate_synthetic_json_samples(1)[0].clone();

    // 1. Compress with dictionary
    let compressed_with_dict = compress_with_dict(&test_payload, DEFAULT_ZSTD_LEVEL, dict.bytes())
        .expect("compress with dict");

    // 2. Compress without dictionary (vanilla zstd)
    let compressed_vanilla =
        compress_with_dict(&test_payload, DEFAULT_ZSTD_LEVEL, &[]).expect("compress vanilla");

    // Dictionary compression should significantly outperform vanilla zstd on small repetitive JSON
    assert!(
        compressed_with_dict.len() < compressed_vanilla.len(),
        "dict len {} should be < vanilla len {}",
        compressed_with_dict.len(),
        compressed_vanilla.len()
    );

    // 3. Decompress with dictionary
    let decompressed =
        decompress_with_dict_bounded(&compressed_with_dict, dict.bytes(), 1024 * 1024, Some(100))
            .expect("decompress with dict");

    assert_eq!(decompressed, test_payload);
}

#[test]
fn test_dict_ratio_evaluation() {
    let samples = generate_synthetic_json_samples(40);
    let dict = DictionaryTrainer::train_from_samples(
        &samples,
        32 * 1024,
        "eval-dict",
        "Evaluation test dictionary",
        1791805000,
    )
    .expect("train dictionary");

    let eval = evaluate_dictionary_ratio(&samples, dict.bytes(), DEFAULT_ZSTD_LEVEL)
        .expect("evaluate ratio");

    assert!(eval.raw_bytes > 0);
    assert!(eval.vanilla_zstd_bytes > 0);
    assert!(eval.dict_zstd_bytes > 0);
    assert!(eval.dict_ratio > eval.vanilla_ratio);
    assert!(eval.extra_savings_pct > 15.0); // usually 30-60% savings on small structured JSON
}

#[test]
fn test_dict_decompression_bomb_defense() {
    let samples = generate_synthetic_json_samples(20);
    let dict = DictionaryTrainer::train_from_samples(
        &samples,
        16 * 1024,
        "bomb-test-dict",
        "Bomb defense test dictionary",
        1791805000,
    )
    .expect("train dictionary");

    let large_payload = vec![b'A'; 200 * 1024]; // 200 KiB
    let compressed =
        compress_with_dict(&large_payload, 1, dict.bytes()).expect("compress large payload");

    // Ceiling of 64 KiB should reject 200 KiB decompression
    let res_bytes = decompress_with_dict_bounded(&compressed, dict.bytes(), 64 * 1024, None);
    assert!(res_bytes.is_err());
    let err = res_bytes.err().unwrap().to_string();
    assert!(err.contains("decompressed size with dictionary exceeds limit"));
}

#[test]
fn test_dict_catalog_lifecycle_and_export_import() {
    let tmp = tempdir().unwrap();
    let catalog_dir = tmp.path().join("dictionaries");
    let export_dir = tmp.path().join("exports");
    fs::create_dir_all(&export_dir).unwrap();

    let catalog = DictionaryCatalog::open_or_create(&catalog_dir).expect("open catalog");

    let samples = generate_synthetic_json_samples(25);
    let dict = DictionaryTrainer::train_from_samples(
        &samples,
        16 * 1024,
        "catalog-dict-v1",
        "Test catalog lifecycle dictionary",
        1791805100,
    )
    .expect("train dictionary");

    let dict_id = dict.dict_id();

    // 1. Register
    catalog.register(&dict).expect("register dict");

    // 2. Lookup by ID and by name
    let by_id = catalog
        .get_by_id(dict_id)
        .expect("get by id")
        .expect("must exist");
    assert_eq!(by_id.name(), "catalog-dict-v1");
    assert_eq!(by_id.bytes(), dict.bytes());

    let by_name = catalog
        .get_by_name("catalog-dict-v1")
        .expect("get by name")
        .expect("must exist");
    assert_eq!(by_name.dict_id(), dict_id);

    // 3. List
    let list = catalog.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].dict_id, dict_id);

    // 4. Export to external file
    let export_path = export_dir.join("exported.zdict");
    catalog
        .export_dictionary(dict_id, &export_path)
        .expect("export dict");
    assert!(export_path.exists());

    // 5. Import into a new separate catalog
    let new_cat_dir = tmp.path().join("new_catalog");
    let new_catalog = DictionaryCatalog::open_or_create(&new_cat_dir).expect("open new catalog");
    let imported = new_catalog
        .import_dictionary(
            &export_path,
            Some("imported-dict-v2"),
            Some("Imported from export"),
            1791805200,
        )
        .expect("import dict");
    assert_eq!(imported.name(), "imported-dict-v2");
    assert_eq!(imported.bytes(), dict.bytes());

    // 6. Delete from original catalog
    let deleted = catalog.delete(dict_id).expect("delete dict");
    assert!(deleted);
    assert!(catalog
        .get_by_id(dict_id)
        .expect("get by id post delete")
        .is_none());
}

#[test]
fn test_dict_trainer_from_directory() {
    let tmp = tempdir().unwrap();
    let corpus_dir = tmp.path().join("corpus");
    fs::create_dir_all(&corpus_dir).unwrap();

    // Create 15 json files
    for i in 0..15 {
        let content = format!(
            r#"{{"id":{},"type":"metric_counter","value":{},"unit":"ms"}}"#,
            i,
            i * 100
        );
        fs::write(corpus_dir.join(format!("metric_{}.json", i)), content).unwrap();
    }

    let dict = DictionaryTrainer::train_from_directory(
        &corpus_dir,
        16 * 1024,
        50,
        "metrics-corpus-dict",
        "Dictionary trained from corpus directory",
        1791805300,
    )
    .expect("train from directory");

    assert_eq!(dict.name(), "metrics-corpus-dict");
    assert_eq!(dict.metadata.sample_count, 15);
    assert!(!dict.bytes().is_empty());
}
