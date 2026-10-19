//! CLI integration tests for cryptographic detached manifest signing & end-to-end attestation (Option BO, SECURITY.md §7).

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
fn test_cli_attest_keygen_and_inspect() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    let pub_path = dir.path().join("signing.key.pub");

    // 1. Generate keypair
    let output = Command::new(velcrux_bin())
        .arg("attest")
        .arg("keygen")
        .arg("--out")
        .arg(&key_path)
        .arg("--pub-out")
        .arg(&pub_path)
        .arg("--comment")
        .arg("release-ci@velcrux.internal")
        .output()
        .expect("execute velcrux attest keygen");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(key_path.exists());
    assert!(pub_path.exists());

    let key_content = fs::read_to_string(&key_path).unwrap();
    assert!(key_content.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(key_content.contains("-----END PRIVATE KEY-----"));

    let pub_content = fs::read_to_string(&pub_path).unwrap();
    assert!(pub_content.starts_with("ssh-ed25519 "));
    assert!(pub_content.contains("release-ci@velcrux.internal"));
}

#[test]
fn test_cli_attest_sign_and_verify_lifecycle() {
    let dir = tempdir().unwrap();
    let payload_dir = dir.path().join("dataset");
    fs::create_dir_all(&payload_dir).unwrap();

    fs::write(payload_dir.join("file1.txt"), b"payload data 1").unwrap();
    fs::write(payload_dir.join("file2.bin"), b"payload data 2").unwrap();

    let key_path = dir.path().join("test.key");
    let pub_path = dir.path().join("test.key.pub");

    // Generate signing key
    let keygen_out = Command::new(velcrux_bin())
        .arg("attest")
        .arg("keygen")
        .arg("--out")
        .arg(&key_path)
        .arg("--pub-out")
        .arg(&pub_path)
        .arg("--comment")
        .arg("auditor@velcrux.internal")
        .output()
        .expect("keygen");
    assert!(keygen_out.status.success());

    // Sign payload directory
    let sig_path = dir.path().join("dataset.sig");
    let sign_out = Command::new(velcrux_bin())
        .arg("attest")
        .arg("sign")
        .arg(&payload_dir)
        .arg("--key")
        .arg(&key_path)
        .arg("--out")
        .arg(&sig_path)
        .arg("--issuer")
        .arg("spiffe://velcrux.internal/auditor")
        .arg("-m")
        .arg("build=v2.0.0")
        .arg("-m")
        .arg("git=f3a8b2")
        .arg("--json")
        .output()
        .expect("sign");

    assert!(
        sign_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&sign_out.stderr)
    );

    let sign_stdout = String::from_utf8_lossy(&sign_out.stdout);
    let sign_json: serde_json::Value = serde_json::from_str(&sign_stdout).expect("valid sign json");
    assert_eq!(sign_json["success"], true);
    assert_eq!(sign_json["issuer"], "spiffe://velcrux.internal/auditor");
    assert_eq!(sign_json["file_count"], 2);

    // Inspect detached signature
    let inspect_out = Command::new(velcrux_bin())
        .arg("attest")
        .arg("inspect")
        .arg(&sig_path)
        .arg("--json")
        .output()
        .expect("inspect");
    assert!(inspect_out.status.success());

    let inspect_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&inspect_out.stdout))
            .expect("valid inspect json");
    assert_eq!(
        inspect_json["payload"]["issuer"],
        "spiffe://velcrux.internal/auditor"
    );
    assert_eq!(inspect_json["payload"]["metadata"]["build"], "v2.0.0");
    assert_eq!(inspect_json["payload"]["metadata"]["git"], "f3a8b2");

    // Verify valid attestation using trusted public keys file
    let verify_out = Command::new(velcrux_bin())
        .arg("attest")
        .arg("verify")
        .arg(&payload_dir)
        .arg("--sig")
        .arg(&sig_path)
        .arg("--trusted-keys")
        .arg(&pub_path)
        .arg("--require-issuer")
        .arg("spiffe://velcrux.internal/auditor")
        .arg("--json")
        .output()
        .expect("verify");

    assert!(
        verify_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&verify_out.stderr)
    );

    let verify_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&verify_out.stdout))
            .expect("valid verify json");
    assert_eq!(verify_json["is_valid"], true);
    assert_eq!(verify_json["status"], "Valid");

    // Tamper with data: modify file1.txt
    fs::write(payload_dir.join("file1.txt"), b"tampered content").unwrap();

    let verify_tampered = Command::new(velcrux_bin())
        .arg("attest")
        .arg("verify")
        .arg(&payload_dir)
        .arg("--sig")
        .arg(&sig_path)
        .arg("--trusted-keys")
        .arg(&pub_path)
        .arg("--json")
        .output()
        .expect("verify tampered");

    assert!(
        !verify_tampered.status.success(),
        "verification should have failed on tampered data"
    );
    let tampered_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&verify_tampered.stdout)).expect("json");
    assert_eq!(tampered_json["is_valid"], false);
    assert_eq!(tampered_json["status"], "HashMismatch");
}

#[test]
fn test_cli_attest_untrusted_signer_rejection() {
    let dir = tempdir().unwrap();
    let payload = dir.path().join("data.txt");
    fs::write(&payload, b"confidential payload").unwrap();

    let rogue_key = dir.path().join("rogue.key");
    let genuine_key = dir.path().join("genuine.key");
    let genuine_pub = dir.path().join("genuine.pub");

    // Generate genuine keypair and trusted signers file
    Command::new(velcrux_bin())
        .args(["attest", "keygen", "--out"])
        .arg(&genuine_key)
        .arg("--pub-out")
        .arg(&genuine_pub)
        .output()
        .expect("keygen genuine");

    // Generate rogue untrusted key
    Command::new(velcrux_bin())
        .args(["attest", "keygen", "--out"])
        .arg(&rogue_key)
        .output()
        .expect("keygen rogue");

    // Sign payload with rogue key
    let sig_path = dir.path().join("rogue.sig");
    Command::new(velcrux_bin())
        .arg("attest")
        .arg("sign")
        .arg(&payload)
        .arg("--key")
        .arg(&rogue_key)
        .arg("--out")
        .arg(&sig_path)
        .output()
        .expect("sign with rogue key");

    // Attempt to verify with genuine trusted keys -> must be rejected
    let verify_rogue = Command::new(velcrux_bin())
        .arg("attest")
        .arg("verify")
        .arg(&payload)
        .arg("--sig")
        .arg(&sig_path)
        .arg("--trusted-keys")
        .arg(&genuine_pub)
        .arg("--json")
        .output()
        .expect("verify rogue");

    assert!(
        !verify_rogue.status.success(),
        "untrusted signer must be rejected"
    );
    let verify_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&verify_rogue.stdout)).expect("json");
    assert_eq!(verify_json["is_valid"], false);
    assert_eq!(verify_json["status"], "UntrustedSigner");
}

#[test]
fn test_cli_sync_with_attestation_signing_and_verification() {
    let src = tempdir().unwrap();
    let dst = tempdir().unwrap();
    let keys_dir = tempdir().unwrap();

    fs::write(src.path().join("doc1.txt"), b"documentation").unwrap();
    fs::write(src.path().join("data.csv"), b"1,2,3\n4,5,6\n").unwrap();

    let sign_key = keys_dir.path().join("sync_authority.key");
    let sign_pub = keys_dir.path().join("sync_authority.pub");

    // Generate sync authority key
    Command::new(velcrux_bin())
        .args(["attest", "keygen", "--out"])
        .arg(&sign_key)
        .arg("--pub-out")
        .arg(&sign_pub)
        .arg("--comment")
        .arg("sync-daemon@internal")
        .output()
        .expect("keygen");

    // Run sync with --sign-key
    let sync_out = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.path())
        .arg(dst.path())
        .arg("--sign-key")
        .arg(&sign_key)
        .arg("--sign-issuer")
        .arg("sync-daemon")
        .output()
        .expect("sync with sign-key");

    assert!(
        sync_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&sync_out.stderr)
    );

    // .velcrux-manifest.sig must exist in destination directory
    let sig_file = dst.path().join(".velcrux-manifest.sig");
    assert!(
        sig_file.exists(),
        "detached signature should be created at {}",
        sig_file.display()
    );

    // Verify attestation at destination
    let verify_out = Command::new(velcrux_bin())
        .arg("attest")
        .arg("verify")
        .arg(dst.path())
        .arg("--trusted-keys")
        .arg(&sign_pub)
        .arg("--require-issuer")
        .arg("sync-daemon")
        .arg("--json")
        .output()
        .expect("verify post-sync");

    assert!(
        verify_out.status.success(),
        "post-sync verification failed: {:?}",
        String::from_utf8_lossy(&verify_out.stderr)
    );

    let v_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&verify_out.stdout)).expect("json");
    assert_eq!(v_json["is_valid"], true);
    assert_eq!(v_json["status"], "Valid");
}
