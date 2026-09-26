//! Integration tests for Option M: Graceful Shutdown (Drain), Commit Journal Replay & Transfer Drain Lifecycle (`OPERATIONS.md` §3, §6).
//!
//! Verifies:
//! 1. Graceful drain lifecycle: active transfer transitions to `RESUMABLE` with staging intact.
//! 2. Commit journal startup recovery:
//!    - `Renamed` rows are finalized to `Committed` alongside their transfer record.
//!    - `Pending` rows are preserved and their transfer record is set to `Resumable`.
//!    - Leftover `Active` transfers from crash/SIGKILL are recovered to `Resumable`.
//! 3. Drain timeout bounding: server enforces bounded drain window without hanging.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::Duration;

use tempfile::tempdir;
use tokio::sync::oneshot;

use velcrux_core::protocol::message::{
    Auth, Hello, Message, TransferBegin, TransferCreate, TransferOp,
};
use velcrux_core::session::{read_frame, write_frame};
use velcrux_core::state::{
    CommitJournalEntry, CommitStatus, Direction, Role, SqliteStateStore, StateStore,
    TransferRecord, TransferStatus,
};
use velcrux_core::transport::quic::ClientBuilder;
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::{Hash, TransferId};
use velcrux_server::server::run_with_shutdown;

struct TestPki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_identity: velcrux_core::transport::quic::ClientIdentity,
}

fn generate_test_pki(identity_name: &str) -> TestPki {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "velcrux-test-ca");
    ca_params.distinguished_name = dn;
    let ca_key = KeyPair::generate().expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");

    // Server cert
    let mut s_params = CertificateParams::default();
    let mut s_dn = DistinguishedName::new();
    s_dn.push(DnType::CommonName, "localhost");
    s_params.distinguished_name = s_dn;
    s_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    s_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    s_params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    let s_key = KeyPair::generate().expect("server key");
    let s_cert = s_params
        .signed_by(&s_key, &ca_cert, &ca_key)
        .expect("sign server");

    // Client cert
    let mut c_params = CertificateParams::default();
    let mut c_dn = DistinguishedName::new();
    c_dn.push(DnType::CommonName, identity_name);
    c_params.distinguished_name = c_dn;
    c_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    c_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    c_params.subject_alt_names = vec![SanType::URI(
        format!("velcrux://identity/{identity_name}")
            .try_into()
            .unwrap(),
    )];
    let c_key = KeyPair::generate().expect("client key");
    let c_cert = c_params
        .signed_by(&c_key, &ca_cert, &ca_key)
        .expect("sign client");

    let c_cert_pem = c_cert.pem();
    let client_certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut c_cert_pem.as_bytes())
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    let client_identity = velcrux_core::transport::quic::ClientIdentity::from_der(
        client_certs,
        c_key.serialize_der(),
    );

    TestPki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: s_cert.pem(),
        server_key_pem: s_key.serialize_pem(),
        client_identity,
    }
}

fn sample_transfer(idem: &str, tid: TransferId, status: TransferStatus) -> TransferRecord {
    TransferRecord {
        transfer_id: tid,
        idempotency_key: idem.into(),
        role: Role::Server,
        direction: Direction::Upload,
        status,
        remote_path: "data/file.bin".into(),
        local_path: String::new(),
        file_size: 1024 * 1024,
        file_hash: Hash::ZERO,
        verified_up_to: 0,
        last_checkpoint_ms: 0,
        bytes_completed: 0,
        staging_relpath: format!("{tid}/data/file.bin"),
        created_ms: 1000,
        updated_ms: 1000,
    }
}

#[tokio::test]
async fn test_server_startup_commit_journal_recovery() {
    let temp = tempdir().unwrap();
    let storage_root = temp.path().join("storage_root");
    let staging_root = temp.path().join("storage_staging");
    let state_db_path = temp.path().join("state.db");
    let config_path = temp.path().join("server.toml");

    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let pki = generate_test_pki("admin");
    let server_crt = temp.path().join("server.crt");
    let server_key = temp.path().join("server.key");
    let ca_crt = temp.path().join("ca.crt");
    std::fs::write(&server_crt, &pki.server_cert_pem).unwrap();
    std::fs::write(&server_key, &pki.server_key_pem).unwrap();
    std::fs::write(&ca_crt, &pki.ca_pem).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&server_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Pre-populate SQLite state store simulating previous state:
    // - t1: In Renamed commit status (disk rename completed, journal uncommitted).
    // - t2: In Pending commit status (rename not yet executed).
    // - t3: Left in Active status without journal entries (unclean shutdown / SIGKILL).
    let store = SqliteStateStore::new(&state_db_path).unwrap();
    let t1 = TransferId::generate();
    let t2 = TransferId::generate();
    let t3 = TransferId::generate();

    store
        .upsert_transfer(&sample_transfer("idem-1", t1, TransferStatus::Active))
        .unwrap();
    store
        .upsert_transfer(&sample_transfer("idem-2", t2, TransferStatus::Active))
        .unwrap();
    store
        .upsert_transfer(&sample_transfer("idem-3", t3, TransferStatus::Active))
        .unwrap();

    store
        .write_journal(&CommitJournalEntry {
            transfer_id: t1,
            file_id: 1,
            remote_path: "data/file1.bin".into(),
            status: CommitStatus::Renamed,
            updated_ms: 1000,
        })
        .unwrap();

    store
        .write_journal(&CommitJournalEntry {
            transfer_id: t2,
            file_id: 1,
            remote_path: "data/file2.bin".into(),
            status: CommitStatus::Pending,
            updated_ms: 1000,
        })
        .unwrap();

    let toml = format!(
        r#"
[network]
listen = "127.0.0.1:0"

[security]
certificate = "{}"
private_key = "{}"
client_ca   = "{}"

[storage]
root     = "{}"
staging  = "{}"
state_db = "{}"
"#,
        server_crt.display(),
        server_key.display(),
        ca_crt.display(),
        storage_root.display(),
        staging_root.display(),
        state_db_path.display()
    );
    std::fs::write(&config_path, toml).unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let _ = shutdown_tx.send(());

    run_with_shutdown(&config_path, async move {
        let _ = shutdown_rx.await;
    })
    .await
    .expect("server startup and recovery");

    // Verify recovered state:
    // - t1 (Renamed) -> finalized to Committed
    let rec1 = store.get_transfer(t1).unwrap();
    assert_eq!(rec1.status, TransferStatus::Committed);

    // - t2 (Pending) -> recovered to Resumable, journal remains Pending for next resume
    let rec2 = store.get_transfer(t2).unwrap();
    assert_eq!(rec2.status, TransferStatus::Resumable);

    // - t3 (Active without journal) -> recovered to Resumable
    let rec3 = store.get_transfer(t3).unwrap();
    assert_eq!(rec3.status, TransferStatus::Resumable);

    // Only t2 should remain pending in journal
    let pending = store.pending_journal().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].transfer_id, t2);
    assert_eq!(pending[0].status, CommitStatus::Pending);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_server_graceful_drain_persists_resumable_state() {
    let temp = tempdir().unwrap();
    let storage_root = temp.path().join("storage_root");
    let staging_root = temp.path().join("storage_staging");
    let state_db_path = temp.path().join("state.db");
    let config_path = temp.path().join("server.toml");

    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let pki = generate_test_pki("replica-client");
    let server_crt = temp.path().join("server.crt");
    let server_key = temp.path().join("server.key");
    let ca_crt = temp.path().join("ca.crt");
    std::fs::write(&server_crt, &pki.server_cert_pem).unwrap();
    std::fs::write(&server_key, &pki.server_key_pem).unwrap();
    std::fs::write(&ca_crt, &pki.ca_pem).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&server_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Choose random ephemeral port for testing
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let toml = format!(
        r#"
[network]
listen = "{server_addr}"
drain_timeout = "5s"

[security]
certificate = "{}"
private_key = "{}"
client_ca   = "{}"

[storage]
root     = "{}"
staging  = "{}"
state_db = "{}"

[[grant]]
identity = "replica-client"
path = "/customerA"
permissions = ["upload", "download", "resume"]
"#,
        server_crt.display(),
        server_key.display(),
        ca_crt.display(),
        storage_root.display(),
        staging_root.display(),
        state_db_path.display()
    );
    std::fs::write(&config_path, toml).unwrap();

    // Start server in background task
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let cfg_path_clone = config_path.clone();
    let server_handle = tokio::spawn(async move {
        run_with_shutdown(&cfg_path_clone, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Connect client using mTLS
    let client_transport = ClientBuilder::new()
        .with_server_roots_pem(pki.ca_pem.as_bytes())
        .unwrap()
        .with_client_identity(pki.client_identity)
        .build()
        .unwrap();

    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");

    let (mut send, mut recv) = conn.open_bi().await.expect("open bi stream");

    // Complete Handshake & Auth
    let hello = Hello::default_client();
    write_frame(send.as_mut(), &Message::Hello(hello), 1)
        .await
        .unwrap();

    let ack_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        ack_frame.type_byte,
        velcrux_core::protocol::message::HELLO_ACK
    );

    let auth = Auth {
        mechanism: velcrux_core::protocol::message::AUTH_MECHANISM_MTLS,
        token: vec![],
    };
    write_frame(send.as_mut(), &Message::Auth(auth), 2)
        .await
        .unwrap();

    let auth_ok = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(auth_ok.type_byte, velcrux_core::protocol::message::AUTH_OK);

    // Initiate Upload
    let idem_key = "idemp-drain-test-001";
    let create = TransferCreate {
        op: TransferOp::Upload,
        idempotency_key: idem_key.into(),
        src_path: "dummy".into(),
        dst_path: "/customerA/live.bin".into(),
        file_size: 4 * 1024 * 1024,
        file_hash: Hash::ZERO,
    };
    write_frame(send.as_mut(), &Message::TransferCreate(create), 3)
        .await
        .unwrap();

    let created_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        created_frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED
    );
    let created = match Message::decode(created_frame.type_byte, created_frame.payload).unwrap() {
        Message::TransferCreated(tc) => tc,
        _ => panic!("expected TransferCreated"),
    };
    let transfer_id = created.transfer_id;

    // Send TRANSFER_BEGIN so server transfer session enters active loop
    let begin = TransferBegin::new(transfer_id);
    write_frame(send.as_mut(), &Message::TransferBegin(begin), 4)
        .await
        .unwrap();

    // Open unidirectional data stream and send preamble
    let mut uni_send = conn.open_uni().await.unwrap();
    let preamble = velcrux_core::protocol::frame::DataPreamble {
        transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    uni_send
        .write_all(bytes::Bytes::from(
            velcrux_core::protocol::frame::encode_data_preamble(&preamble).to_vec(),
        ))
        .await
        .unwrap();

    // Give server actor time to open staging and upsert transfer to Active
    tokio::time::sleep(Duration::from_millis(200)).await;

    let store = SqliteStateStore::new(&state_db_path).unwrap();
    let initial_rec = store
        .get_transfer(transfer_id)
        .expect("transfer record exists");
    assert_eq!(initial_rec.status, TransferStatus::Active);

    // Fire graceful shutdown / drain
    let _ = shutdown_tx.send(());

    // Drop client connection to simulate network drop during drain
    drop(uni_send);
    drop(send);
    drop(recv);
    drop(conn);

    // Await server graceful shutdown
    let res = server_handle.await.expect("join handle");
    assert!(res.is_ok(), "server exited cleanly: {:?}", res);

    // Verify transfer state was safely persisted as RESUMABLE
    let final_rec = store
        .get_transfer(transfer_id)
        .expect("transfer record in state.db");
    assert_eq!(
        final_rec.status,
        TransferStatus::Resumable,
        "interrupted transfer must be marked RESUMABLE per OPERATIONS.md §3"
    );

    // Verify staging directory was preserved on disk
    let expected_staging = staging_root.join(transfer_id.to_string());
    assert!(
        expected_staging.exists(),
        "staging must be preserved for resume"
    );
}

#[tokio::test]
async fn test_server_drain_timeout_exceeded_safety() {
    let temp = tempdir().unwrap();
    let storage_root = temp.path().join("storage_root");
    let staging_root = temp.path().join("storage_staging");
    let state_db_path = temp.path().join("state.db");
    let config_path = temp.path().join("server.toml");

    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let pki = generate_test_pki("admin");
    let server_crt = temp.path().join("server.crt");
    let server_key = temp.path().join("server.key");
    let ca_crt = temp.path().join("ca.crt");
    std::fs::write(&server_crt, &pki.server_cert_pem).unwrap();
    std::fs::write(&server_key, &pki.server_key_pem).unwrap();
    std::fs::write(&ca_crt, &pki.ca_pem).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&server_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let toml = format!(
        r#"
[network]
listen = "127.0.0.1:0"
drain_timeout = "100ms"

[security]
certificate = "{}"
private_key = "{}"
client_ca   = "{}"

[storage]
root     = "{}"
staging  = "{}"
state_db = "{}"
"#,
        server_crt.display(),
        server_key.display(),
        ca_crt.display(),
        storage_root.display(),
        staging_root.display(),
        state_db_path.display()
    );
    std::fs::write(&config_path, toml).unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_handle = tokio::spawn(async move {
        run_with_shutdown(&config_path, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(());

    // Should complete within a few hundred ms even with drain timeout
    let res = tokio::time::timeout(Duration::from_secs(3), server_handle)
        .await
        .expect("drain timeout bounding must not hang")
        .expect("join handle");

    assert!(res.is_ok());
}
