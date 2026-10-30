//! Integration tests for Option CG: Zero-Trust Decentralized Identity (DID)
//! & Verifiable Credential Attestation Mesh (`ADR-049`).

#![forbid(unsafe_code)]

use std::process::Command;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_did_status_text_and_json() {
    // 1. Human-readable text output
    let output = Command::new(velcrux_bin())
        .arg("did")
        .arg("status")
        .output()
        .expect("execute did status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Zero-Trust DID & Verifiable Credential Engine Status ==="));
    assert!(stdout.contains("DID Resolutions:"));
    assert!(stdout.contains("VCs Issued:"));
    assert!(stdout.contains("VCs Verified:"));
    assert!(stdout.contains("VC Verification Fails:"));
    assert!(stdout.contains("Active Delegations:"));
    assert!(stdout.contains("Last Latency:"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("did")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute did status json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).expect("parse status json");
    assert!(v.get("did_resolutions_total").is_some());
    assert!(v.get("did_vc_issued_total").is_some());
    assert!(v.get("did_vc_verified_total").is_some());
    assert!(v.get("did_vc_verification_failures_total").is_some());
    assert!(v.get("did_verification_latency_nanoseconds").is_some());
    assert!(v.get("did_active_delegations").is_some());
}

#[test]
fn test_cli_did_generate_key_and_peer() {
    // 1. Generate did:key (default)
    let output = Command::new(velcrux_bin())
        .arg("did")
        .arg("generate")
        .output()
        .expect("execute did generate");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Method:                 did:key"));
    assert!(stdout.contains("DID:                    did:key:z6M"));
    assert!(stdout.contains("Private Key PKCS#8:     3051020101300506032b657004220420"));

    // 2. Generate did:peer with JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("did")
        .arg("generate")
        .arg("--peer")
        .arg("--json")
        .output()
        .expect("execute did generate peer json");

    assert!(json_out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse generate json");
    let did_str = v["did"].as_str().expect("did as string");
    assert!(did_str.starts_with("did:peer:0z6M"));
    assert_eq!(v["did_method"], "did:peer");
    assert!(v["private_key_pkcs8_hex"].as_str().is_some());
    assert_eq!(v["did_document"]["id"], did_str);
}

#[test]
fn test_cli_did_resolve() {
    // 1. Generate a DID
    let gen_out = Command::new(velcrux_bin())
        .arg("did")
        .arg("generate")
        .arg("--json")
        .output()
        .expect("generate did");
    assert!(gen_out.status.success());
    let gen_v: serde_json::Value = serde_json::from_slice(&gen_out.stdout).expect("parse gen json");
    let did = gen_v["did"].as_str().unwrap();

    // 2. Resolve the DID
    let resolve_out = Command::new(velcrux_bin())
        .arg("did")
        .arg("resolve")
        .arg("--did")
        .arg(did)
        .arg("--json")
        .output()
        .expect("resolve did");
    assert!(resolve_out.status.success());
    let res_v: serde_json::Value =
        serde_json::from_slice(&resolve_out.stdout).expect("parse resolve json");
    assert_eq!(res_v["did"], did);
    assert!(res_v["did_document"]["verificationMethod"].is_array());
    assert!(res_v["did_document"]["authentication"].is_array());
    assert!(res_v["did_document"]["assertionMethod"].is_array());

    // 3. Resolve invalid DID fails gracefully
    let bad_out = Command::new(velcrux_bin())
        .arg("did")
        .arg("resolve")
        .arg("--did")
        .arg("did:example:invalid")
        .output()
        .expect("resolve bad did");
    assert!(!bad_out.status.success());
}

#[test]
fn test_cli_did_issue_and_verify_vc() {
    // 1. Generate issuer identity
    let gen_out = Command::new(velcrux_bin())
        .arg("did")
        .arg("generate")
        .arg("--json")
        .output()
        .expect("generate did");
    assert!(gen_out.status.success());
    let gen_v: serde_json::Value = serde_json::from_slice(&gen_out.stdout).expect("parse gen json");
    let issuer_did = gen_v["did"].as_str().unwrap();
    let issuer_sk = gen_v["private_key_pkcs8_hex"].as_str().unwrap();

    // 2. Issue a Verifiable Credential
    let issue_out = Command::new(velcrux_bin())
        .arg("did")
        .arg("issue-vc")
        .arg("--issuer-sk")
        .arg(issuer_sk)
        .arg("--subject-did")
        .arg(issuer_did)
        .arg("--tenant")
        .arg("tenant-finance")
        .arg("--paths")
        .arg("/ledgers/*,/reports/*")
        .arg("--ops")
        .arg("upload,download")
        .arg("--json")
        .output()
        .expect("issue vc");

    assert!(
        issue_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&issue_out.stderr)
    );
    let vc_str = String::from_utf8_lossy(&issue_out.stdout)
        .trim()
        .to_string();
    let vc_json: serde_json::Value = serde_json::from_str(&vc_str).expect("parse vc json");
    assert_eq!(vc_json["issuer"], issuer_did);
    assert_eq!(vc_json["credentialSubject"]["tenantId"], "tenant-finance");
    assert_eq!(vc_json["proof"]["type"], "Ed25519Signature2020");

    // 3. Verify the VC (valid case with matching path and op)
    let verify_ok = Command::new(velcrux_bin())
        .arg("did")
        .arg("verify-vc")
        .arg("--vc")
        .arg(&vc_str)
        .arg("--requested-path")
        .arg("/ledgers/2026/q3.parquet")
        .arg("--requested-op")
        .arg("upload")
        .arg("--json")
        .output()
        .expect("verify vc ok");

    assert!(
        verify_ok.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&verify_ok.stderr)
    );
    let ok_v: serde_json::Value =
        serde_json::from_slice(&verify_ok.stdout).expect("parse verify ok json");
    assert_eq!(ok_v["is_valid"], true);
    assert_eq!(ok_v["issuer_did"], issuer_did);
    assert_eq!(ok_v["subject_did"], issuer_did);
    assert_eq!(ok_v["tenant_id"], "tenant-finance");

    // 4. Verify unauthorized path rejection
    let verify_bad_path = Command::new(velcrux_bin())
        .arg("did")
        .arg("verify-vc")
        .arg("--vc")
        .arg(&vc_str)
        .arg("--requested-path")
        .arg("/secret/keys.pem")
        .arg("--requested-op")
        .arg("upload")
        .output()
        .expect("verify vc bad path");
    assert!(!verify_bad_path.status.success());
    let stderr = String::from_utf8_lossy(&verify_bad_path.stderr);
    assert!(stderr.contains("Path '/secret/keys.pem' is not authorized"));

    // 5. Verify unauthorized operation rejection
    let verify_bad_op = Command::new(velcrux_bin())
        .arg("did")
        .arg("verify-vc")
        .arg("--vc")
        .arg(&vc_str)
        .arg("--requested-path")
        .arg("/ledgers/2026/q3.parquet")
        .arg("--requested-op")
        .arg("admin")
        .output()
        .expect("verify vc bad op");
    assert!(!verify_bad_op.status.success());
    let stderr_op = String::from_utf8_lossy(&verify_bad_op.stderr);
    assert!(stderr_op.contains("Operation 'admin' is not authorized"));
}

#[test]
fn test_cli_did_delegation_chain_verification() {
    // 1. Generate parent keypair
    let parent_gen = Command::new(velcrux_bin())
        .arg("did")
        .arg("generate")
        .arg("--json")
        .output()
        .expect("generate parent did");
    assert!(parent_gen.status.success());
    let parent_v: serde_json::Value =
        serde_json::from_slice(&parent_gen.stdout).expect("parse parent json");
    let parent_did = parent_v["did"].as_str().unwrap();
    let parent_sk = parent_v["private_key_pkcs8_hex"].as_str().unwrap();

    // 2. Issue parent VC with delegation depth = 2
    let parent_issue = Command::new(velcrux_bin())
        .arg("did")
        .arg("issue-vc")
        .arg("--issuer-sk")
        .arg(parent_sk)
        .arg("--subject-did")
        .arg(parent_did)
        .arg("--tenant")
        .arg("tenant-corp")
        .arg("--paths")
        .arg("/shared/*")
        .arg("--ops")
        .arg("upload,download,sync")
        .arg("--delegation-depth")
        .arg("2")
        .arg("--json")
        .output()
        .expect("issue parent vc");
    assert!(parent_issue.status.success());
    let parent_vc_str = String::from_utf8_lossy(&parent_issue.stdout)
        .trim()
        .to_string();

    // 3. Generate child keypair
    let child_gen = Command::new(velcrux_bin())
        .arg("did")
        .arg("generate")
        .arg("--json")
        .output()
        .expect("generate child did");
    assert!(child_gen.status.success());
    let child_v: serde_json::Value =
        serde_json::from_slice(&child_gen.stdout).expect("parse child json");
    let child_did = child_v["did"].as_str().unwrap();

    // 4. Parent delegates to child (allowed paths subset, allowed ops subset, delegation depth 1)
    let child_issue = Command::new(velcrux_bin())
        .arg("did")
        .arg("issue-vc")
        .arg("--issuer-sk")
        .arg(parent_sk)
        .arg("--subject-did")
        .arg(child_did)
        .arg("--tenant")
        .arg("tenant-corp")
        .arg("--paths")
        .arg("/shared/team_b/*")
        .arg("--ops")
        .arg("upload")
        .arg("--delegation-depth")
        .arg("1")
        .arg("--parent-vc")
        .arg(&parent_vc_str)
        .arg("--json")
        .output()
        .expect("issue child delegated vc");

    assert!(
        child_issue.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&child_issue.stderr)
    );
    let child_vc_str = String::from_utf8_lossy(&child_issue.stdout)
        .trim()
        .to_string();

    // 5. Verify the delegated child VC
    let verify_child = Command::new(velcrux_bin())
        .arg("did")
        .arg("verify-vc")
        .arg("--vc")
        .arg(&child_vc_str)
        .arg("--requested-path")
        .arg("/shared/team_b/data.bin")
        .arg("--requested-op")
        .arg("upload")
        .arg("--json")
        .output()
        .expect("verify child vc");

    assert!(
        verify_child.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&verify_child.stderr)
    );
    let verify_v: serde_json::Value =
        serde_json::from_slice(&verify_child.stdout).expect("parse child verify json");
    assert_eq!(verify_v["is_valid"], true);
    assert_eq!(verify_v["subject_did"], child_did);
    assert_eq!(verify_v["delegation_chain_depth"], 1);

    // 6. Escalation attempt: delegate requesting paths outside parent scope should fail at issue time
    let bad_delegation = Command::new(velcrux_bin())
        .arg("did")
        .arg("issue-vc")
        .arg("--issuer-sk")
        .arg(parent_sk)
        .arg("--subject-did")
        .arg(child_did)
        .arg("--tenant")
        .arg("tenant-corp")
        .arg("--paths")
        .arg("/unauthorized/*")
        .arg("--ops")
        .arg("upload")
        .arg("--parent-vc")
        .arg(&parent_vc_str)
        .output()
        .expect("issue bad delegation");

    assert!(!bad_delegation.status.success());
    let err_str = String::from_utf8_lossy(&bad_delegation.stderr);
    assert!(err_str.contains("is not authorized by parent allowed paths"));
}

#[test]
fn test_cli_did_benchmark() {
    // 1. Text benchmark
    let output = Command::new(velcrux_bin())
        .arg("did")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .output()
        .expect("run did benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Zero-Trust DID & VC Benchmark (20 iters) ==="));
    assert!(stdout.contains("Resolution Latency:"));
    assert!(stdout.contains("Issuance Latency:"));
    assert!(stdout.contains("Verification Latency:"));

    // 2. JSON benchmark
    let json_out = Command::new(velcrux_bin())
        .arg("did")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .arg("--json")
        .output()
        .expect("run did benchmark json");

    assert!(json_out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse benchmark json");
    assert_eq!(v["iterations"], 20);
    assert!(v["resolution_latency_nanoseconds"].as_f64().unwrap() > 0.0);
    assert!(v["issuance_latency_nanoseconds"].as_f64().unwrap() > 0.0);
    assert!(v["verification_latency_nanoseconds"].as_f64().unwrap() > 0.0);
    assert!(v["resolution_ops_per_second"].as_f64().unwrap() > 0.0);
    assert!(v["issuance_ops_per_second"].as_f64().unwrap() > 0.0);
}
