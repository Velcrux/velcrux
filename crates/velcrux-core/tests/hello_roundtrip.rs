//! M1 exit test (`docs/ARCHITECTURE.md` §12):
//! > QUIC connect, control stream, HELLO — `velcrux ping` round trip,
//! > version negotiation
//!
//! The full QUIC round trip is exercised end-to-end: mTLS handshake,
//! HELLO / HELLO_ACK capability negotiation, PING / PONG, and BYE.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::session::{ClientSession, ServerConn, ServerStats};
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, QuicTransport, ServerBuilder,
    TransportConfigTunables,
};
use velcrux_core::transport::Transport;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile;
use tokio::time::timeout;
use tracing_subscriber::EnvFilter;

// Silence "imported but unused" warnings on the dev-only helpers below.
#[allow(dead_code)]
struct _Unused;

// Silence "imported but unused" warnings on the dev-only helpers below.

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((data.len() + 2) / 3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

fn wrap_64(s: &str) -> Vec<String> {
    s.as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

/// Build a self-signed dev CA. Returns the CA's cert PEM, key PEM, and
/// the underlying rcgen `KeyPair` so child certs can be signed without
/// round-tripping through the PEM.
struct DevCa {
    cert_pem: String,
    key_der: Vec<u8>,
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

fn build_dev_ca() -> DevCa {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "velcrux-test-ca");
    ca_params.distinguished_name = dn;

    let ca_key = KeyPair::generate().expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");

    // Re-derive the key in PKCS#8 DER form for the rustls `PrivateKey`.
    // rcgen's `serialize_der()` returns the PKCS#8 bytes for a KeyPair.
    let key_der = ca_key.serialize_der();

    DevCa {
        cert_pem: ca_cert.pem(),
        key_der,
        ca_cert,
        ca_key,
    }
}

fn build_server_cert(ca: &DevCa) -> (Vec<Certificate>, PrivateKey) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "velcrux-test-server");
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];

    let key = KeyPair::generate().expect("server key");
    let cert = params
        .signed_by(&key, &ca.ca_cert, &ca.ca_key)
        .expect("sign server cert");
    let cert_pem = cert.pem();
    let key_der = key.serialize_der();

    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .expect("parse server cert PEM")
        .into_iter()
        .map(Certificate)
        .collect();
    (certs, PrivateKey(key_der))
}

fn build_client_identity(ca: &DevCa, name: &str) -> ClientIdentity {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = vec![SanType::URI(
        format!("velcrux://identity/{name}").try_into().unwrap(),
    )];
    let key = KeyPair::generate().expect("client key");
    let cert = params
        .signed_by(&key, &ca.ca_cert, &ca.ca_key)
        .expect("sign client cert");
    let cert_pem = cert.pem();
    let key_der = key.serialize_der();
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .expect("parse client cert PEM")
        .into_iter()
        .map(Certificate)
        .collect();
    ClientIdentity::from_der(certs, key_der)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_and_ping_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
    // The M1 exit test (per docs/ARCHITECTURE.md §12).
    let ca = build_dev_ca();
    let (server_certs, server_key) = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "dev-user");
    // The client needs to trust the *server* cert directly (not the CA).
    // In M1 the server presents its leaf cert (chain length 1) — but the
    // client also needs to trust the CA chain for the leaf to verify.
    // Easiest path: build a CA bundle that includes both the CA and the
    // server leaf, and load it as the client root. The CA signs the leaf
    // so this is correct.
    let mut server_bundle = ca.cert_pem.clone();
    // Append the server leaf to the bundle so the client can verify
    // chain[0]=leaf → chain[1]=CA.
    // For tests, just trust the CA: the client will walk the chain and
    // find a trusted root.
    let _ = &mut server_bundle;

    let server_addr: SocketAddr = "127.0.0.1:17645".parse().unwrap();

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);

    let transport = ServerBuilder::new()
        .with_server_cert(server_certs, server_key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("client CA roots")
        .with_tunables(TransportConfigTunables {
            receive_window: 4 * 1024 * 1024,
            stream_receive_window: 4 * 1024 * 1024,
            max_concurrent_streams: 4,
            idle_timeout: Duration::from_secs(10),
            keepalive: Duration::from_secs(2),
            initial_rtt: Duration::from_millis(50),
        })
        .build(server_addr)
        .expect("server build");

    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(client_identity)
            .build()
            .expect("client build"),
    );

    let stats = Arc::new(ServerStats::default());
    let server_caps_clone = server_caps;
    let stats_for_server = Arc::clone(&stats);
    let server_task = tokio::spawn(async move {
        eprintln!("server: accepting");
        let conn = transport.accept().await.expect("server accept");
        eprintln!("server: accepted");
        let actor = ServerConn::new(server_caps_clone, "velcrux-test-server", stats_for_server);
        let r = actor.run(&conn).await;
        eprintln!("server: actor finished: {r:?}");
        r
    });

    let mut session = timeout(
        Duration::from_secs(5),
        ClientSession::connect(client_transport, server_addr, "localhost"),
    )
    .await
    .expect("client connect timeout")
    .expect("client connect");
    eprintln!("client: connected, HELLO_ACK received");

    let negotiated = session.negotiated();
    assert_eq!(negotiated.version, 1);
    assert!(negotiated.capabilities.has(Capability::Blake3));
    assert!(negotiated.capabilities.has(Capability::FixedChunking));

    let rtt = timeout(Duration::from_secs(5), session.ping())
        .await
        .expect("ping timeout")
        .expect("ping");
    eprintln!("PING rtt = {rtt} ms");
    assert!(rtt < 5_000, "rtt is unreasonably large");

    session.bye().await.ok();

    let _ = timeout(Duration::from_secs(3), server_task)
        .await
        .expect("server did not finish in time");
}

#[allow(dead_code)]
fn _suppress_unused() {
    let _ = base64_encode;
}
