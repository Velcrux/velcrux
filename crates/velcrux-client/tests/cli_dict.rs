//! Integration tests for Zstandard pre-trained dictionary learning CLI (Option BE).

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
fn test_cli_dict_lifecycle_table() {
    let tmp = tempdir().unwrap();
    let sample_dir = tmp.path().join("samples");
    let cat_dir = tmp.path().join("dictionaries");
    let export_file = tmp.path().join("exported.zdict");
    fs::create_dir_all(&sample_dir).unwrap();

    // Generate 12 sample json files
    for i in 0..12 {
        let content = format!(
            r#"{{"event":"metric_record","node_id":"cluster-node-{}","value":{},"unit":"ms","status":"HEALTHY","trace":"tx_{:08x}"}}"#,
            i % 4,
            i * 42,
            i * 1337
        );
        fs::write(sample_dir.join(format!("sample_{}.json", i)), content).unwrap();
    }

    // 1. Train dictionary
    let train_out = Command::new(velcrux_bin())
        .arg("dict")
        .arg("train")
        .arg(&sample_dir)
        .arg("--name")
        .arg("metrics-dict-v1")
        .arg("--dict-size")
        .arg("16384")
        .arg("--desc")
        .arg("Metrics sample dictionary")
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("train dictionary");

    assert!(
        train_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&train_out.stderr)
    );
    let train_str = String::from_utf8_lossy(&train_out.stdout);
    assert!(train_str.contains("ZSTANDARD PRE-TRAINED DICTIONARY GENERATED"));
    assert!(train_str.contains("Name                 : metrics-dict-v1"));
    assert!(train_str.contains("Ingested Samples     : 12"));

    let dict_id_str = train_str
        .lines()
        .find(|l| l.contains("Dictionary ID"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim())
        .expect("parse dict ID");
    let dict_id: u32 = dict_id_str.parse().expect("dict_id should be u32");

    // 2. List dictionaries
    let list_out = Command::new(velcrux_bin())
        .arg("dict")
        .arg("list")
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("list dictionaries");

    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("ZSTANDARD PRE-TRAINED DICTIONARY CATALOG"));
    assert!(list_str.contains("metrics-dict-v1"));
    assert!(list_str.contains("Total Dictionaries   : 1"));

    // 3. Test & evaluate dictionary compression ratio
    let test_out = Command::new(velcrux_bin())
        .arg("dict")
        .arg("test")
        .arg(dict_id.to_string())
        .arg(&sample_dir)
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("test dictionary");

    assert!(test_out.status.success());
    let test_str = String::from_utf8_lossy(&test_out.stdout);
    assert!(test_str.contains("DICTIONARY COMPRESSION PERFORMANCE EVALUATION"));
    assert!(test_str.contains("metrics-dict-v1"));
    assert!(test_str.contains("Bandwidth Reduction"));

    // 4. Export dictionary
    let export_out = Command::new(velcrux_bin())
        .arg("dict")
        .arg("export")
        .arg(dict_id.to_string())
        .arg(&export_file)
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("export dictionary");

    assert!(export_out.status.success());
    assert!(export_file.exists());

    // 5. Delete dictionary
    let delete_out = Command::new(velcrux_bin())
        .arg("dict")
        .arg("delete")
        .arg(dict_id.to_string())
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("delete dictionary");

    assert!(delete_out.status.success());
    let delete_str = String::from_utf8_lossy(&delete_out.stdout);
    assert!(delete_str.contains("successfully deleted"));

    // Verify empty catalog
    let list_post = Command::new(velcrux_bin())
        .arg("dict")
        .arg("list")
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("list dictionaries post delete");
    assert!(list_post.status.success());
    let post_str = String::from_utf8_lossy(&list_post.stdout);
    assert!(post_str.contains("Total Dictionaries   : 0"));
}

#[test]
fn test_cli_dict_json_mode() {
    let tmp = tempdir().unwrap();
    let sample_dir = tmp.path().join("json_samples");
    let cat_dir = tmp.path().join("json_cat");
    fs::create_dir_all(&sample_dir).unwrap();

    for i in 0..10 {
        let content = format!(
            r#"{{"sensor_id":"sen_{}","reading":{}.5,"timestamp":1791800000}}"#,
            i,
            i * 11
        );
        fs::write(sample_dir.join(format!("s_{}.json", i)), content).unwrap();
    }

    // 1. Train in JSON mode
    let train_out = Command::new(velcrux_bin())
        .arg("--json")
        .arg("dict")
        .arg("train")
        .arg(&sample_dir)
        .arg("--name")
        .arg("sensor-telemetry")
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("train json");

    assert!(train_out.status.success());
    let train_val: serde_json::Value =
        serde_json::from_slice(&train_out.stdout).expect("parse train json");
    assert_eq!(train_val["event"], "dict_trained");
    assert_eq!(train_val["dictionary"]["name"], "sensor-telemetry");
    let dict_id = train_val["dictionary"]["dict_id"].as_u64().unwrap() as u32;

    // 2. List in JSON mode
    let list_out = Command::new(velcrux_bin())
        .arg("--json")
        .arg("dict")
        .arg("list")
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("list json");

    assert!(list_out.status.success());
    let list_val: serde_json::Value =
        serde_json::from_slice(&list_out.stdout).expect("parse list json");
    assert_eq!(list_val["event"], "dict_list");
    assert_eq!(list_val["count"], 1);

    // 3. Test in JSON mode
    let test_out = Command::new(velcrux_bin())
        .arg("--json")
        .arg("dict")
        .arg("test")
        .arg(dict_id.to_string())
        .arg(&sample_dir)
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("test json");

    assert!(test_out.status.success());
    let test_val: serde_json::Value =
        serde_json::from_slice(&test_out.stdout).expect("parse test json");
    assert_eq!(test_val["event"], "dict_test");
    assert_eq!(test_val["dict_id"], dict_id);
    assert!(test_val["evaluation"]["raw_bytes"].as_u64().unwrap() > 0);

    // 4. Delete in JSON mode
    let del_out = Command::new(velcrux_bin())
        .arg("--json")
        .arg("dict")
        .arg("delete")
        .arg(dict_id.to_string())
        .arg("--dict-dir")
        .arg(&cat_dir)
        .output()
        .expect("delete json");

    assert!(del_out.status.success());
    let del_val: serde_json::Value =
        serde_json::from_slice(&del_out.stdout).expect("parse delete json");
    assert_eq!(del_val["event"], "dict_deleted");
    assert_eq!(del_val["deleted"], true);
}
