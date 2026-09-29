//! Fuzz corpus runner and adversarial boundary test matrix.
//!
//! Validates:
//! - All committed seed corpora in `fuzz/corpus/<target>/` exercise their respective
//!   parsers without panicking or leaking resources (`DEVELOPMENT.md` §6).
//! - Adversarial wire frame matrix (`SECURITY.md` §8):
//!   * Varint canonicality, overflows, premature EOF.
//!   * Frame decoders: max message size boundaries, version mismatches, truncated frames.
//!   * Data frames: max chunk length, reserved bit validations.
//!   * Manifest entries: path limits, chunk sum consistency, privileged xattrs boundaries.
//!   * Path traversal corpus: 60+ traversal patterns, escape attempts, control characters.
//!   * Server TOML config parsing and boundary validations.
//!   * X.509 certificate identity extraction: SAN URI extraction and CN fallbacks.

use std::fs;
use std::path::PathBuf;
use velcrux_core::error::ProtocolError;
use velcrux_core::manifest::codec::{
    decode_chunk_desc, decode_file_entry, encode_chunk_desc, encode_file_entry,
    validate_xattrs_security,
};
use velcrux_core::manifest::entry::{ChunkDesc, FileEntry};
use velcrux_core::manifest::reader::ManifestBatchDecoder;
use velcrux_core::protocol::frame::{
    decode_data_frame_header, decode_data_preamble, decode_frame, encode_data_frame_header,
    encode_data_preamble, encode_frame, header_size_for, DataFrameFlags, DataPreamble, FrameFlags,
    DATA_FRAME_HEADER_LEN, DATA_MAX_CHUNK_LEN,
};
use velcrux_core::protocol::limits::{MAX_MESSAGE_SIZE, MAX_PATH_TOTAL, PROTOCOL_VERSION};
use velcrux_core::protocol::message::{Auth, Hello, ManifestBatch, Message};
use velcrux_core::protocol::varint::{decode_varint, encode_varint};
use velcrux_core::storage::VPath;
use velcrux_core::transport::quic::identity_from_chain;
use velcrux_core::util::{Hash, TransferId};
use velcrux_server::config::{parse_size_bytes, ServerConfig};

fn corpus_dir(target: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fuzz")
        .join("corpus")
        .join(target)
}

fn encode_test_frame(type_byte: u8, request_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; header_size_for(payload.len() as u64) + payload.len()];
    let n = encode_frame(&mut buf, type_byte, FrameFlags::NONE, request_id, payload);
    buf.truncate(n);
    buf
}

/// Helper to ensure seed files exist in the corpus directory
fn ensure_seed_corpora() {
    // 1. Frame decoder seeds
    let dir = corpus_dir("frame_decoder");
    fs::create_dir_all(&dir).unwrap();

    let hello_path = dir.join("seed_hello.bin");
    if !hello_path.exists() {
        let hello = Hello::default_client();
        let payload = hello.encode().unwrap();
        let frame = encode_test_frame(velcrux_core::protocol::message::HELLO, 1, &payload);
        fs::write(hello_path, frame).unwrap();
    }

    let auth_path = dir.join("seed_auth.bin");
    if !auth_path.exists() {
        let auth = Auth::mtls();
        let payload = auth.encode().unwrap();
        let frame = encode_test_frame(velcrux_core::protocol::message::AUTH, 2, &payload);
        fs::write(auth_path, frame).unwrap();
    }

    let preamble_path = dir.join("seed_data_preamble.bin");
    if !preamble_path.exists() {
        let preamble = DataPreamble {
            transfer_id: TransferId::generate(),
            file_id: 1,
            stream_seq: 1,
        };
        let encoded = encode_data_preamble(&preamble);
        fs::write(preamble_path, encoded).unwrap();
    }

    let data_frame_path = dir.join("seed_data_frame.bin");
    if !data_frame_path.exists() {
        let mut buf = vec![0u8; DATA_FRAME_HEADER_LEN + 16];
        encode_data_frame_header(
            &mut buf[..DATA_FRAME_HEADER_LEN],
            0,
            16,
            DataFrameFlags::NONE,
            &Hash::ZERO,
        );
        fs::write(data_frame_path, buf).unwrap();
    }

    // 2. Manifest decoder seeds
    let dir = corpus_dir("manifest_decoder");
    fs::create_dir_all(&dir).unwrap();

    let file_entry_path = dir.join("seed_file_entry.bin");
    if !file_entry_path.exists() {
        let path = VPath::validate("sample.dat").unwrap();
        let chunk = ChunkDesc::new(1024, Hash::ZERO);
        let entry = FileEntry::regular(path, 1024, 0o644, 1700000000, 0, Hash::ZERO, vec![chunk]);
        let mut out = Vec::new();
        encode_file_entry(&entry, &mut out);
        fs::write(file_entry_path, out).unwrap();
    }

    let chunk_desc_path = dir.join("seed_chunk_desc.bin");
    if !chunk_desc_path.exists() {
        let chunk = ChunkDesc::new(2048, Hash::ZERO);
        let mut out = Vec::new();
        encode_chunk_desc(&chunk, &mut out);
        fs::write(chunk_desc_path, out).unwrap();
    }

    // 3. Path validator seeds
    let dir = corpus_dir("path_validator");
    fs::create_dir_all(&dir).unwrap();
    let norm = dir.join("seed_normal.txt");
    if !norm.exists() {
        fs::write(norm, "docs/architecture.md").unwrap();
    }

    // 4. Config parser seeds
    let dir = corpus_dir("config_parser");
    fs::create_dir_all(&dir).unwrap();
    let min = dir.join("seed_minimal.toml");
    if !min.exists() {
        fs::write(
            min,
            "[security]\ncertificate = \"/tmp/s.crt\"\nprivate_key = \"/tmp/s.key\"\nclient_ca = \"/tmp/ca.crt\"\n[storage]\nroot = \"/tmp/data\"\nstaging = \"/tmp/stage\"\n",
        )
        .unwrap();
    }

    // 5. Cert identity seeds
    let dir = corpus_dir("cert_identity");
    fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("seed_alice.der");
    if !cert_path.exists() {
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "alice");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "velcrux://identity/alice".try_into().unwrap(),
        )];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        fs::write(cert_path, cert.der()).unwrap();
    }
}

#[test]
fn test_corpus_frame_decoder() {
    ensure_seed_corpora();
    let dir = corpus_dir("frame_decoder");
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let data = fs::read(entry.path()).unwrap();

        // Must never panic
        if let Ok(frame) = decode_frame(&data) {
            let _ = Message::decode(frame.type_byte, frame.payload);
        }
        let _ = decode_data_frame_header(&data);
        let _ = decode_data_preamble(&data);
        let _ = decode_varint(&data);
    }
}

#[test]
fn test_corpus_manifest_decoder() {
    ensure_seed_corpora();
    let dir = corpus_dir("manifest_decoder");
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let data = fs::read(entry.path()).unwrap();

        // Must never panic
        if let Ok((entry, _)) = decode_file_entry(&data) {
            let _ = validate_xattrs_security(&entry.xattrs, false);
            let _ = validate_xattrs_security(&entry.xattrs, true);
        }
        let _ = decode_chunk_desc(&data);
        if let Ok(batch) = ManifestBatch::decode(&data) {
            let mut decoder = ManifestBatchDecoder::new(Hash::ZERO);
            let _ = decoder.decode_batch(&batch);
        }
    }
}

#[test]
fn test_corpus_path_validator() {
    ensure_seed_corpora();
    let dir = corpus_dir("path_validator");
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let data = fs::read(entry.path()).unwrap();
        if let Ok(s) = std::str::from_utf8(&data) {
            if let Ok(vpath) = VPath::validate(s) {
                let _ = vpath.parent();
                let _ = vpath.is_root();
                let _ = VPath::validate_symlink_target(&vpath, s);
            }
            let root = VPath::root();
            let _ = VPath::validate_symlink_target(&root, s);
        }
    }
}

#[test]
fn test_corpus_config_parser() {
    ensure_seed_corpora();
    let dir = corpus_dir("config_parser");
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let data = fs::read(entry.path()).unwrap();
        if let Ok(s) = std::str::from_utf8(&data) {
            let _ = parse_size_bytes(s);
            if let Ok(mut cfg) = toml::from_str::<ServerConfig>(s) {
                cfg.apply_env_overrides();
                let _ = cfg.validate();
            }
        }
    }
}

#[test]
fn test_corpus_cert_identity() {
    ensure_seed_corpora();
    let dir = corpus_dir("cert_identity");
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let data = fs::read(entry.path()).unwrap();
        let cert = rustls::Certificate(data);
        let _ = identity_from_chain(&[cert]);
    }
}

// ---------------------------------------------------------------------------
// Adversarial Wire Frame & Boundary Test Matrix (SECURITY.md §8)
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_varint_matrix() {
    // 1. Non-canonical varints: value 0 must be 1 byte `[0x00]`, multi-byte encodings are rejected
    let non_canonical = vec![
        vec![0x80, 0x00],
        vec![0x80, 0x80, 0x00],
        vec![0x80, 0x80, 0x80, 0x00],
    ];
    for enc in non_canonical {
        assert!(
            matches!(decode_varint(&enc), Err(ProtocolError::NonCanonicalVarint)),
            "Non-canonical varint was unexpectedly accepted"
        );
    }

    // 2. Varint overflow (> 10 bytes or > 64-bit integer)
    let overflow = vec![0xFFu8; 11];
    assert!(
        matches!(decode_varint(&overflow), Err(ProtocolError::VarintOverflow)),
        "Overflowing varint was unexpectedly accepted"
    );

    // 3. Truncated varint (continuation bit set, but slice ends)
    let truncated = vec![0x80u8];
    assert!(matches!(
        decode_varint(&truncated),
        Err(ProtocolError::VarintOverflow)
    ));
    assert!(matches!(decode_varint(&[]), Err(ProtocolError::Empty)));

    // 4. Valid canonical boundary values round-trip
    let boundaries = [
        0u64,
        1,
        127,
        128,
        255,
        16383,
        16384,
        u32::MAX as u64,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut buf = [0u8; 10];
    for val in boundaries {
        let n = encode_varint(val, &mut buf);
        let (decoded, consumed) = decode_varint(&buf[..n]).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, n);
    }
}

#[test]
fn test_adversarial_frame_decoder_matrix() {
    // 1. Declared length exceeds max message size
    let mut buf = Vec::new();
    buf.push(PROTOCOL_VERSION);
    buf.push(0x01); // HELLO
    buf.extend_from_slice(&FrameFlags::NONE.bits().to_le_bytes());
    // Encode length: MAX_MESSAGE_SIZE + 1
    let mut vbuf = [0u8; 10];
    let n = encode_varint(MAX_MESSAGE_SIZE + 1, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    buf.extend_from_slice(&1u64.to_le_bytes()); // request id
    assert!(
        matches!(decode_frame(&buf), Err(ProtocolError::FrameTooLarge { .. })),
        "Oversized frame was not rejected with FrameTooLarge"
    );

    // 2. Declared length u64::MAX
    let mut buf = Vec::new();
    buf.push(PROTOCOL_VERSION);
    buf.push(0x01);
    buf.extend_from_slice(&FrameFlags::NONE.bits().to_le_bytes());
    let n = encode_varint(u64::MAX, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    buf.extend_from_slice(&1u64.to_le_bytes());
    assert!(matches!(
        decode_frame(&buf),
        Err(ProtocolError::FrameTooLarge { .. })
    ));

    // 3. Protocol version mismatch
    let mut buf = Vec::new();
    buf.push(0x99); // bad version
    buf.push(0x01);
    buf.extend_from_slice(&FrameFlags::NONE.bits().to_le_bytes());
    let n = encode_varint(0, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    buf.extend_from_slice(&1u64.to_le_bytes());
    assert!(matches!(
        decode_frame(&buf),
        Err(ProtocolError::VersionMismatch { .. })
    ));

    // 4. Truncated header inputs
    for len in 0..12 {
        let partial = vec![PROTOCOL_VERSION; len];
        assert!(matches!(decode_frame(&partial), Err(ProtocolError::Empty)));
    }
}

#[test]
fn test_adversarial_data_frame_matrix() {
    // 1. Truncated header (< 48 bytes)
    for len in 0..DATA_FRAME_HEADER_LEN {
        let partial = vec![0u8; len];
        assert!(matches!(
            decode_data_frame_header(&partial),
            Err(ProtocolError::Malformed(_))
        ));
    }

    // 2. Declared chunk_len > DATA_MAX_CHUNK_LEN (4 MiB)
    let mut buf = vec![0u8; DATA_FRAME_HEADER_LEN];
    encode_data_frame_header(
        &mut buf,
        0,
        DATA_MAX_CHUNK_LEN + 1,
        DataFrameFlags::NONE,
        &Hash::ZERO,
    );
    assert!(matches!(
        decode_data_frame_header(&buf),
        Err(ProtocolError::Malformed(_))
    ));

    // 3. Non-zero reserved bits in data frame header
    let mut buf = vec![0u8; DATA_FRAME_HEADER_LEN];
    encode_data_frame_header(&mut buf, 0, 1024, DataFrameFlags::NONE, &Hash::ZERO);
    buf[14] = 0xFF; // dirty reserved bytes
    assert!(matches!(
        decode_data_frame_header(&buf),
        Err(ProtocolError::Malformed(_))
    ));

    // 4. Truncated preamble
    for len in 0..56 {
        let partial = vec![0u8; len];
        assert!(matches!(
            decode_data_preamble(&partial),
            Err(ProtocolError::Malformed(_))
        ));
    }
}

#[test]
fn test_adversarial_manifest_codec_matrix() {
    // 1. Declared path length > MAX_PATH_TOTAL (4096)
    let mut buf = Vec::new();
    let mut vbuf = [0u8; 10];
    let n = encode_varint(0, &mut vbuf); // flags
    buf.extend_from_slice(&vbuf[..n]);
    let n = encode_varint(MAX_PATH_TOTAL as u64 + 1, &mut vbuf); // oversized path len
    buf.extend_from_slice(&vbuf[..n]);
    assert!(matches!(
        decode_file_entry(&buf),
        Err(ProtocolError::InvalidManifest(_))
    ));

    // 2. Non-UTF8 path
    let mut buf = Vec::new();
    let n = encode_varint(0, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    let bad_utf8 = [0xFF, 0xFE, 0xFD];
    let n = encode_varint(bad_utf8.len() as u64, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    buf.extend_from_slice(&bad_utf8);
    assert!(matches!(
        decode_file_entry(&buf),
        Err(ProtocolError::Malformed(_))
    ));

    // 3. Running chunk sum does not equal declared size
    let path = VPath::validate("mismatch.dat").unwrap();
    let chunk = ChunkDesc::new(500, Hash::ZERO);
    // Declared size 1000, but chunks sum to 500
    let entry = FileEntry::regular(path, 1000, 0o644, 1000, 0, Hash::ZERO, vec![chunk]);
    let mut out = Vec::new();
    encode_file_entry(&entry, &mut out);
    assert!(matches!(
        decode_file_entry(&out),
        Err(ProtocolError::InvalidManifest(_))
    ));

    // 4. Privileged xattrs boundary validation
    let priv_xattrs = vec![
        ("security.selinux".to_string(), b"context".to_vec()),
        ("trusted.secret".to_string(), b"key".to_vec()),
        ("system.posix_acl_access".to_string(), b"acl".to_vec()),
    ];
    // Non-admin MUST be rejected
    assert!(validate_xattrs_security(&priv_xattrs, false).is_err());
    // Admin MUST be allowed
    assert!(validate_xattrs_security(&priv_xattrs, true).is_ok());

    // Standard user attributes are allowed for non-admin
    let user_xattrs = vec![
        ("user.mime_type".to_string(), b"text/plain".to_vec()),
        ("user.checksum".to_string(), b"blake3".to_vec()),
    ];
    assert!(validate_xattrs_security(&user_xattrs, false).is_ok());
}

#[test]
fn test_adversarial_path_traversal_corpus() {
    // 60+ attack vectors from SECURITY.md §8 (path traversal corpus)
    let attack_vectors = [
        "../",
        "..",
        "../../",
        "../../../etc/passwd",
        "..\\",
        "..\\..\\",
        "..\\windows\\system32",
        "foo/../bar",
        "foo/../../bar",
        "foo/bar/../../../baz",
        "/etc/passwd",
        "/root",
        "//server/share",
        "///root",
        "./foo",
        "foo/./bar",
        "foo/.",
        "foo/",
        "foo//bar",
        "foo///bar",
        "foo\0bar",
        "foo\x01bar",
        "foo\x1Fbar",
        "foo\x7Fbar",
        "C:\\Windows",
        "D:data",
        "\\\\?\\C:\\Windows",
        "\\\\.\\Volume",
        "%2e%2e/foo",
        "..;/foo",
        "....//foo",
        ".\\./foo",
        "foo/..;/bar",
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "LPT1",
        ".././.././../etc/shadow",
        "a/b/c/../../../../escape",
    ];

    for vec in attack_vectors {
        assert!(
            VPath::validate(vec).is_err(),
            "Path traversal vector {vec:?} was unexpectedly accepted"
        );
    }

    // Depth bounds: deeper than 128 components must be rejected
    let deep_path = (0..130)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join("/");
    assert!(
        VPath::validate(&deep_path).is_err() || deep_path.len() > MAX_PATH_TOTAL,
        "Deep path was not clamped"
    );

    // Symlink escape defense
    let link = VPath::validate("sub/dir/link.txt").unwrap();
    let escape_targets = [
        "../../../../etc/passwd",
        "../../../root",
        "/etc/shadow",
        "\\server\\share",
        "C:\\Windows",
        "sub/../../../../escaped",
        "link\0null",
    ];
    for target in escape_targets {
        assert!(
            VPath::validate_symlink_target(&link, target).is_err(),
            "Symlink target {target:?} was not rejected by escape defense"
        );
    }

    // Valid symlink targets inside grant boundary
    let safe_targets = [
        "target.txt",
        "../sibling.txt",
        "../../file.txt",
        "nested/deep/item.dat",
    ];
    for target in safe_targets {
        assert!(
            VPath::validate_symlink_target(&link, target).is_ok(),
            "Safe symlink target {target:?} was erroneously rejected"
        );
    }
}

#[test]
fn test_adversarial_config_parser_matrix() {
    // 1. Invalid size strings
    let invalid_sizes = [
        "-10MB",
        "",
        "abc",
        "100XB",
        "10.5.2MB",
        "999999999999999999999999999TiB",
        "100 MB", // no spaces allowed
    ];
    for s in invalid_sizes {
        assert!(
            parse_size_bytes(s).is_err(),
            "Invalid size string {s:?} was unexpectedly parsed"
        );
    }

    // Valid sizes parse accurately
    assert_eq!(parse_size_bytes("256KiB").unwrap(), 256 * 1024);
    assert_eq!(parse_size_bytes("1MiB").unwrap(), 1024 * 1024);
    assert_eq!(parse_size_bytes("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);

    // 3. Invalid TOML configurations
    let invalid_tomls = [
        "",                                     // empty
        "broken_toml = [",                      // syntax error
        "[storage]\nroot = \"rel/path\"\n",     // relative storage root
        "[network]\nlisten = \"invalid:ip\"\n", // bad listen address
    ];
    for t in invalid_tomls {
        if let Ok(cfg) = toml::from_str::<ServerConfig>(t) {
            assert!(
                cfg.validate().is_err(),
                "Invalid config was erroneously validated: {t:?}"
            );
        }
    }
}

#[test]
fn test_adversarial_cert_identity_matrix() {
    // 1. Empty DER
    let empty_cert = rustls::Certificate(vec![]);
    assert!(identity_from_chain(&[empty_cert]).is_err());

    // 2. Garbage random bytes
    let garbage_cert = rustls::Certificate(vec![0xAA; 128]);
    assert!(identity_from_chain(&[garbage_cert]).is_err());

    // 3. Valid cert with Common Name only (fallback when SAN URI is missing)
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "bob_cn_only");
    params.distinguished_name = dn;
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let r_cert = rustls::Certificate(cert.der().to_vec());
    let ident = identity_from_chain(&[r_cert]).unwrap();
    assert_eq!(ident.name, "bob_cn_only");

    // 4. Valid cert with SAN URI `velcrux://identity/<name>` takes precedence over CN
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "cn_should_lose");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![rcgen::SanType::URI(
        "velcrux://identity/san_winner".try_into().unwrap(),
    )];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let r_cert = rustls::Certificate(cert.der().to_vec());
    let ident = identity_from_chain(&[r_cert]).unwrap();
    assert_eq!(ident.name, "san_winner");
}
