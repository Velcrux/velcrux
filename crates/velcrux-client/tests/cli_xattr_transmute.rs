//! Integration tests for Option BP: Cross-Platform Extended Attribute (xattr)
//! & NFSv4 ACL Transmutation Engine (`CLAUDE.md` §4 Open Question #2, `ADR-032`).

use std::fs;
use std::process::Command;
use tempfile::tempdir;

use velcrux_core::storage::{
    decode_xattrs_canonical, encode_xattrs_canonical, xattr_sidecar_path, AcePermissions,
    AcePrincipal, AclPolicy, CanonicalAce, CanonicalAcl, PlatformOs, XattrPolicy, XattrTransmuter,
};
use velcrux_core::sync::{
    plan_directory_diff_with_options, scan_dir_entries, DirectorySyncOptions,
};

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_sync_xattr_transmute_linux_to_macos() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    let file_path = src.join("document.pdf");
    fs::write(&file_path, b"dummy document payload").unwrap();

    // Create Linux-style xattrs with "user." namespace
    let linux_attrs = vec![
        ("user.mime_type".to_string(), b"application/pdf".to_vec()),
        (
            "user.com.apple.quarantine".to_string(),
            b"0081;632b8fa4;Safari;".to_vec(),
        ),
        (
            "user.com.apple.metadata:kMDItemFinderComment".to_string(),
            b"confidential release report".to_vec(),
        ),
    ];
    let sidecar_src = xattr_sidecar_path(&file_path);
    fs::write(&sidecar_src, encode_xattrs_canonical(&linux_attrs)).unwrap();

    // Run velcrux sync with default transmute policy
    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .arg("--xattr-policy")
        .arg("transmute")
        .output()
        .expect("execute velcrux sync");

    assert!(
        output.status.success(),
        "sync failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dst_file = dst.join("document.pdf");
    assert!(dst_file.exists());

    let sidecar_dst = xattr_sidecar_path(&dst_file);
    assert!(sidecar_dst.exists(), "staged xattr sidecar must exist");

    let dst_bytes = fs::read(&sidecar_dst).unwrap();
    let dst_attrs = decode_xattrs_canonical(&dst_bytes).unwrap();

    // Check that target attributes are present and correctly formatted
    #[cfg(target_os = "macos")]
    {
        // On macOS target, "user." is stripped
        let names: Vec<String> = dst_attrs.into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"mime_type".to_string()));
        assert!(names.contains(&"com.apple.quarantine".to_string()));
        assert!(names.contains(&"com.apple.metadata:kMDItemFinderComment".to_string()));
    }
    #[cfg(target_os = "linux")]
    {
        // On Linux target, "user." is retained
        let names: Vec<String> = dst_attrs.into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"user.mime_type".to_string()));
    }
}

#[test]
fn test_cli_sync_xattr_policy_strip() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    let file_path = src.join("data.txt");
    fs::write(&file_path, b"test data").unwrap();

    let attrs = vec![("user.tag".to_string(), b"production".to_vec())];
    let sidecar_src = xattr_sidecar_path(&file_path);
    fs::write(&sidecar_src, encode_xattrs_canonical(&attrs)).unwrap();

    // Run velcrux sync with --xattr-policy strip
    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .arg("--xattr-policy")
        .arg("strip")
        .output()
        .expect("execute velcrux sync");

    assert!(output.status.success());

    let dst_file = dst.join("data.txt");
    assert!(dst_file.exists());

    let sidecar_dst = xattr_sidecar_path(&dst_file);
    assert!(
        !sidecar_dst.exists(),
        "sidecar must not exist when xattr-policy is strip"
    );
}

#[test]
fn test_cli_sync_xattr_policy_strict() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    let file_path = src.join("raw.txt");
    fs::write(&file_path, b"raw data").unwrap();

    let attrs = vec![("user.exact_custom_name".to_string(), b"val123".to_vec())];
    let sidecar_src = xattr_sidecar_path(&file_path);
    fs::write(&sidecar_src, encode_xattrs_canonical(&attrs)).unwrap();

    // Run velcrux sync with --xattr-policy strict
    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .arg("--xattr-policy")
        .arg("strict")
        .output()
        .expect("execute velcrux sync");

    assert!(output.status.success());

    let dst_file = dst.join("raw.txt");
    let sidecar_dst = xattr_sidecar_path(&dst_file);
    assert!(sidecar_dst.exists());

    let dst_bytes = fs::read(&sidecar_dst).unwrap();
    let dst_attrs = decode_xattrs_canonical(&dst_bytes).unwrap();
    assert_eq!(dst_attrs.len(), 1);
    assert_eq!(dst_attrs[0].0, "user.exact_custom_name");
    assert_eq!(dst_attrs[0].1, b"val123");
}

#[test]
fn test_engine_cross_platform_acl_transmutation() {
    // 1. Simulate Linux -> macOS ACL transmutation
    let mut posix_acl = CanonicalAcl::new();
    posix_acl.add_entry(CanonicalAce {
        principal: AcePrincipal::Owner,
        ace_type: velcrux_core::storage::AceType::Allow,
        permissions: AcePermissions::from_posix_mode(true, true, true),
        flags: Default::default(),
    });
    posix_acl.add_entry(CanonicalAce {
        principal: AcePrincipal::NamedUser(501, Some("developer".into())),
        ace_type: velcrux_core::storage::AceType::Allow,
        permissions: AcePermissions::from_posix_mode(true, false, true),
        flags: Default::default(),
    });
    posix_acl.add_entry(CanonicalAce {
        principal: AcePrincipal::NamedGroup(20, Some("staff".into())),
        ace_type: velcrux_core::storage::AceType::Allow,
        permissions: AcePermissions::from_posix_mode(true, false, false),
        flags: Default::default(),
    });

    let binary_posix = posix_acl.to_posix_acl_binary();
    let linux_to_mac = XattrTransmuter::new(PlatformOs::Linux, PlatformOs::MacOS).with_admin(true);

    let (darwin_name, darwin_payload) = linux_to_mac
        .transmute_entry("system.posix_acl_access", &binary_posix)
        .expect("must transmute to darwin ACL");

    assert_eq!(darwin_name, "com.apple.acl.text");
    let darwin_text = String::from_utf8(darwin_payload).unwrap();
    assert!(darwin_text.contains("user:owner:allow:read,write,execute"));
    assert!(darwin_text.contains("user:501:allow:read,execute"));
    assert!(darwin_text.contains("group:20:allow:read"));

    // 2. Transmute back from Darwin text to Linux binary
    let mac_to_linux = XattrTransmuter::new(PlatformOs::MacOS, PlatformOs::Linux).with_admin(true);

    let (posix_name, posix_payload) = mac_to_linux
        .transmute_entry("com.apple.acl.text", darwin_text.as_bytes())
        .expect("must transmute to posix ACL");

    assert_eq!(posix_name, "system.posix_acl_access");
    let roundtrip_acl = CanonicalAcl::from_posix_acl_binary(&posix_payload, false).unwrap();
    assert_eq!(roundtrip_acl.entries.len(), 3);
}

#[test]
fn test_reconciliation_diff_recognizes_transmuted_equality() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    let src_file = src.join("app.conf");
    let dst_file = dst.join("app.conf");
    fs::write(&src_file, b"content=123").unwrap();
    fs::write(&dst_file, b"content=123").unwrap();

    // Source has Linux user.mime_type
    let src_attrs = vec![("user.mime_type".to_string(), b"text/plain".to_vec())];
    fs::write(
        xattr_sidecar_path(&src_file),
        encode_xattrs_canonical(&src_attrs),
    )
    .unwrap();

    // Destination on macOS has transmuted mime_type
    let dst_attrs = vec![("mime_type".to_string(), b"text/plain".to_vec())];
    fs::write(
        xattr_sidecar_path(&dst_file),
        encode_xattrs_canonical(&dst_attrs),
    )
    .unwrap();

    let src_scanned = scan_dir_entries(&src).unwrap();
    let dst_scanned = scan_dir_entries(&dst).unwrap();

    let options = DirectorySyncOptions::default()
        .with_xattr_policy(XattrPolicy::Transmute)
        .with_acl_policy(AclPolicy::Transmute);

    let plan = plan_directory_diff_with_options(&src_scanned, &dst_scanned, &options);

    // Because user.mime_type transmutes to mime_type, file is correctly recognized as UNCHANGED!
    assert_eq!(
        plan.summary.files_unchanged, 1,
        "Transmuted xattrs must be recognized as unchanged"
    );
    assert_eq!(plan.summary.files_modified, 0);
}
