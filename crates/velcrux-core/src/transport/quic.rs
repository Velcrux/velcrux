//! `QuicTransport` — the only [`Transport`](super::Transport) implementation.
//!
//! QUIC does reliability, ordering within a stream, encryption, congestion
//! control, and packet authentication. We do not reimplement any of that
//! (`CLAUDE.md` §1 invariant #1). The rustls/QUIC-TLS configuration is built
//! here; the QUIC driver is `quinn`.
//!
//! ALPN is `RAVEN/1` (`PROTOCOL.md` header). mTLS is required: a connection
//! without a client certificate is rejected on the server, and the client
//! always verifies the server certificate against a configured trust root
//! and checks the SNI hostname (`SECURITY.md` §2, §3).
//!
//! Tunables follow `OPERATIONS.md` §4.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::{Certificate, ClientConfig as RustlsClientConfig, PrivateKey, RootCertStore};
use sha2::{Digest, Sha256};

use crate::error::{Result, TransportError};
use crate::protocol::limits::{
    ALPN, MAX_IDENTITY_LEN, QUIC_IDLE_TIMEOUT_SECS, QUIC_KEEPALIVE_SECS,
};
use crate::transport::identity::Identity;
use crate::transport::stats::TransportStats;

use super::{
    BiRecv, BiRecvStream, BiSend, BiSendStream, Connection, Transport, UniRecv, UniRecvStream,
    UniSend, UniSendStream,
};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Runtime tunables for a [`QuicTransport`].
#[derive(Debug, Clone)]
pub struct TransportConfigTunables {
    pub receive_window: u64,
    pub stream_receive_window: u64,
    pub max_concurrent_streams: u32,
    pub idle_timeout: Duration,
    pub keepalive: Duration,
    pub initial_rtt: Duration,
}

impl Default for TransportConfigTunables {
    fn default() -> Self {
        Self {
            receive_window: 384 * 1024 * 1024,
            stream_receive_window: 384 * 1024 * 1024,
            max_concurrent_streams: 32,
            idle_timeout: Duration::from_secs(QUIC_IDLE_TIMEOUT_SECS),
            keepalive: Duration::from_secs(QUIC_KEEPALIVE_SECS),
            initial_rtt: Duration::from_millis(150),
        }
    }
}

impl TransportConfigTunables {
    /// Build a quinn `TransportConfig` from these tunables.
    pub fn build_quinn(&self) -> TransportConfig {
        let mut c = TransportConfig::default();
        c.receive_window(VarInt::from_u64(self.receive_window).expect("receive_window fits"))
            .stream_receive_window(
                VarInt::from_u64(self.stream_receive_window).expect("stream_receive_window fits"),
            )
            .max_concurrent_uni_streams(VarInt::from_u32(self.max_concurrent_streams))
            .max_concurrent_bidi_streams(VarInt::from_u32(self.max_concurrent_streams))
            .max_idle_timeout(Some(
                self.idle_timeout.try_into().expect("idle_timeout fits"),
            ))
            .keep_alive_interval(Some(self.keepalive))
            .initial_rtt(self.initial_rtt);
        c
    }
}

// ---------------------------------------------------------------------------
// Client builder
// ---------------------------------------------------------------------------

/// Builder for the client-side `QuicTransport`.
pub struct ClientBuilder {
    server_roots: RootCertStore,
    client_identity: Option<ClientIdentity>,
    tunables: TransportConfigTunables,
}

impl ClientBuilder {
    /// New builder with default tunables and no client identity.
    pub fn new() -> Self {
        Self {
            server_roots: RootCertStore::empty(),
            client_identity: None,
            tunables: TransportConfigTunables::default(),
        }
    }

    /// Add DER-encoded server certificates to the trust store.
    pub fn with_server_roots(mut self, certs: &[Certificate]) -> Self {
        for c in certs {
            self.server_roots.add(c).expect("adding trusted root");
        }
        self
    }

    /// Add DER-encoded server certificates from a PEM bundle.
    pub fn with_server_roots_pem(mut self, pem: &[u8]) -> Result<Self> {
        let certs = rustls_pemfile::certs(&mut &pem[..])
            .map_err(|e| crate::error::VelcruxError::Config(format!("server roots PEM: {e}")))?;
        for c in certs {
            self.server_roots
                .add(&Certificate(c))
                .expect("adding trusted root");
        }
        Ok(self)
    }

    /// Set the client identity (cert + key) for mTLS.
    pub fn with_client_identity(mut self, identity: ClientIdentity) -> Self {
        self.client_identity = Some(identity);
        self
    }

    /// Override the default tunables.
    pub fn with_tunables(mut self, tunables: TransportConfigTunables) -> Self {
        self.tunables = tunables;
        self
    }

    /// Consume the builder and produce a `QuicTransport`.
    pub fn build(self) -> Result<QuicTransport> {
        let mut tls_cfg = if let Some(id) = self.client_identity {
            RustlsClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(self.server_roots)
                .with_client_auth_cert(id.cert_chain, id.key)
                .map_err(TransportError::Tls)?
        } else {
            RustlsClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(self.server_roots)
                .with_no_client_auth()
        };
        tls_cfg.alpn_protocols = vec![ALPN.to_vec()];

        let mut client_cfg = ClientConfig::new(Arc::new(tls_cfg));
        client_cfg.transport_config(Arc::new(self.tunables.build_quinn()));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| TransportError::Endpoint(e.to_string()))?;
        endpoint.set_default_client_config(client_cfg);
        Ok(QuicTransport { endpoint })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A client mTLS identity: leaf certificate chain + private key.
#[derive(Clone)]
pub struct ClientIdentity {
    pub cert_chain: Vec<Certificate>,
    pub key: PrivateKey,
}

impl ClientIdentity {
    /// Construct from a `Vec<rustls::Certificate>` and PKCS#8 DER.
    pub fn from_der(cert_chain: Vec<Certificate>, key_pkcs8_der: Vec<u8>) -> Self {
        Self {
            cert_chain,
            key: PrivateKey(key_pkcs8_der),
        }
    }
}

// ---------------------------------------------------------------------------
// Server builder
// ---------------------------------------------------------------------------

/// Builder for the server-side `QuicTransport`.
pub struct ServerBuilder {
    cert_chain: Vec<Certificate>,
    key: PrivateKey,
    client_roots: RootCertStore,
    tunables: TransportConfigTunables,
}

impl ServerBuilder {
    /// New builder with default tunables.
    pub fn new() -> Self {
        Self {
            cert_chain: Vec::new(),
            key: PrivateKey(Vec::new()),
            client_roots: RootCertStore::empty(),
            tunables: TransportConfigTunables::default(),
        }
    }

    /// Set the server leaf certificate and key.
    pub fn with_server_cert(mut self, cert_chain: Vec<Certificate>, key: PrivateKey) -> Self {
        self.cert_chain = cert_chain;
        self.key = key;
        self
    }

    /// Add DER-encoded client CA certificates to the verifier store.
    pub fn with_client_ca_roots(mut self, certs: &[Certificate]) -> Self {
        for c in certs {
            self.client_roots.add(c).expect("adding client root");
        }
        self
    }

    /// Add DER-encoded client CA certificates from a PEM bundle.
    pub fn with_client_ca_roots_pem(mut self, pem: &[u8]) -> Result<Self> {
        let certs = rustls_pemfile::certs(&mut &pem[..])
            .map_err(|e| crate::error::VelcruxError::Config(format!("client CA roots PEM: {e}")))?;
        for c in certs {
            self.client_roots
                .add(&Certificate(c))
                .expect("adding client root");
        }
        Ok(self)
    }

    /// Override the default tunables.
    pub fn with_tunables(mut self, tunables: TransportConfigTunables) -> Self {
        self.tunables = tunables;
        self
    }

    /// Consume the builder and bind to `addr`. Returns a `QuicTransport`.
    ///
    /// The server requires and verifies a client certificate against the
    /// configured `client_roots`. Connections without a valid client cert
    /// are rejected during the TLS handshake.
    pub fn build(self, addr: SocketAddr) -> Result<QuicTransport> {
        let client_roots = self.client_roots;

        let verifier = rustls::server::AllowAnyAuthenticatedClient::new(client_roots);

        let mut tls_cfg = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(self.cert_chain, self.key)
            .map_err(TransportError::Tls)?;
        tls_cfg.alpn_protocols = vec![ALPN.to_vec()];

        let mut server_cfg = ServerConfig::with_crypto(Arc::new(tls_cfg));
        server_cfg.transport_config(Arc::new(self.tunables.build_quinn()));

        let endpoint = Endpoint::server(server_cfg, addr)
            .map_err(|e| TransportError::Endpoint(e.to_string()))?;
        Ok(QuicTransport { endpoint })
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// QuicTransport (the impl)
// ---------------------------------------------------------------------------

/// The QUIC transport. Wraps a single `quinn::Endpoint`.
pub struct QuicTransport {
    /// The underlying quinn endpoint. Client-only on the client, accept-only
    /// on the server.
    endpoint: Endpoint,
}

impl QuicTransport {
    /// Local address the transport endpoint is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}

#[async_trait]
impl Transport for QuicTransport {
    type Conn = QuicConnection;

    async fn connect(&self, addr: SocketAddr, sni: &str) -> Result<Self::Conn> {
        let conn = self
            .endpoint
            .connect(addr, sni)
            .map_err(|e| TransportError::Endpoint(e.to_string()))?;
        let conn = conn.await?;
        Ok(QuicConnection { inner: conn })
    }

    async fn accept(&self) -> Result<Self::Conn> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| TransportError::Endpoint("endpoint closed".into()))?;
        let conn = incoming.await?;
        Ok(QuicConnection { inner: conn })
    }
}

/// A live QUIC connection.
pub struct QuicConnection {
    inner: quinn::Connection,
}

impl QuicConnection {
    /// Returns the underlying quinn connection.
    pub fn quinn(&self) -> &quinn::Connection {
        &self.inner
    }
}

#[async_trait]
impl Connection for QuicConnection {
    async fn open_bi(&self) -> Result<(BiSend, BiRecv)> {
        let (s, r) = self.inner.open_bi().await?;
        Ok((Box::new(QuicSend(s)), Box::new(QuicRecv(r))))
    }

    async fn accept_bi(&self) -> Result<(BiSend, BiRecv)> {
        let (s, r) = self.inner.accept_bi().await?;
        Ok((Box::new(QuicSend(s)), Box::new(QuicRecv(r))))
    }

    async fn open_uni(&self) -> Result<UniSend> {
        let s = self.inner.open_uni().await?;
        Ok(Box::new(QuicSend(s)))
    }

    async fn accept_uni(&self) -> Result<UniRecv> {
        let r = self.inner.accept_uni().await?;
        Ok(Box::new(QuicRecv(r)))
    }

    fn peer_identity(&self) -> Option<Identity> {
        let any = self.inner.peer_identity()?;
        let chain: Vec<Certificate> = match any.downcast::<Vec<Certificate>>() {
            Ok(c) => *c,
            Err(_) => return None,
        };
        identity_from_chain(&chain).ok()
    }

    fn stats(&self) -> TransportStats {
        let s = self.inner.stats();
        TransportStats {
            rtt: Some(s.path.rtt),
            rtt_var: None,
            bytes_in_flight: 0,
            cwnd: s.path.cwnd,
            loss_events: s.path.lost_packets,
            retransmits: 0,
        }
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(VarInt::from_u32(code), reason);
    }
}

// ---------------------------------------------------------------------------
// Stream wrappers
// ---------------------------------------------------------------------------

/// Wraps a `quinn::SendStream` to implement `BiSendStream` or `UniSendStream`.
pub struct QuicSend(quinn::SendStream);

#[async_trait]
impl BiSendStream for QuicSend {
    async fn write_all(&mut self, data: Bytes) -> Result<()> {
        self.0.write_all(&data).await?;
        Ok(())
    }
    async fn finish(&mut self) -> Result<()> {
        self.0.finish().await?;
        Ok(())
    }
}

#[async_trait]
impl UniSendStream for QuicSend {
    async fn write_all(&mut self, data: Bytes) -> Result<()> {
        self.0.write_all(&data).await?;
        Ok(())
    }
    async fn finish(&mut self) -> Result<()> {
        self.0.finish().await?;
        Ok(())
    }
}

/// Wraps a `quinn::RecvStream` to implement `BiRecvStream` or `UniRecvStream`.
pub struct QuicRecv(quinn::RecvStream);

#[async_trait]
impl BiRecvStream for QuicRecv {
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>> {
        let c = self
            .0
            .read_chunk(max, true)
            .await
            .map_err(|e| TransportError::ReadError(e.to_string()))?;
        Ok(c.map(|ch| ch.bytes))
    }
    async fn read_exact(&mut self, n: usize) -> Result<Option<Bytes>> {
        let mut buf = vec![0u8; n];
        match self.0.read_exact(&mut buf).await {
            Ok(()) => Ok(Some(Bytes::from(buf))),
            Err(quinn::ReadExactError::FinishedEarly) => Ok(None),
            Err(e) => Err(TransportError::ReadError(e.to_string()).into()),
        }
    }
}

#[async_trait]
impl UniRecvStream for QuicRecv {
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>> {
        let c = self
            .0
            .read_chunk(max, true)
            .await
            .map_err(|e| TransportError::ReadError(e.to_string()))?;
        Ok(c.map(|ch| ch.bytes))
    }
    async fn read_exact(&mut self, n: usize) -> Result<Option<Bytes>> {
        let mut buf = vec![0u8; n];
        match self.0.read_exact(&mut buf).await {
            Ok(()) => Ok(Some(Bytes::from(buf))),
            Err(quinn::ReadExactError::FinishedEarly) => Ok(None),
            Err(e) => Err(TransportError::ReadError(e.to_string()).into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Identity extraction (M4: real x509 parsing per SECURITY.md §2)
// ---------------------------------------------------------------------------

/// URI prefix that carries the Velcrux identity in a certificate SAN
/// (`SECURITY.md` §2): `velcrux://identity/<name>`.
const IDENTITY_URI_PREFIX: &str = "velcrux://identity/";

/// Derive the [`Identity`] from a peer certificate chain.
///
/// Per `SECURITY.md` §2 the identity *name* is taken from the leaf
/// certificate's Subject Alternative Name URI `velcrux://identity/<name>`
/// when present, otherwise from the subject Common Name. The chain itself
/// has already been cryptographically verified by rustls during the
/// QUIC/TLS handshake — mTLS is mandatory (see the module header and
/// ADR-001). This function only *extracts and validates the name*; it does
/// not establish trust and must never be used to do so.
///
/// The issuer fingerprint is the SHA-256 of the second cert in the chain,
/// or the leaf itself for a single-cert (self-signed dev PKI) chain. Both
/// fingerprints are redacted in `Identity`'s `Debug` (`SECURITY.md` §9).
pub fn identity_from_chain(chain: &[Certificate]) -> Result<Identity> {
    let leaf = chain
        .first()
        .ok_or(crate::error::ProtocolError::InvalidIdentity("empty chain"))?;
    let leaf_fp = hex_fingerprint(leaf.as_ref());
    let issuer_fp = if chain.len() > 1 {
        hex_fingerprint(chain[1].as_ref())
    } else {
        // Self-signed (or single-cert chain) — issuer == leaf.
        leaf_fp.clone()
    };
    let name = extract_identity_name(leaf.as_ref())?;
    Ok(Identity::new(name, issuer_fp, leaf_fp))
}

/// Extract the identity name from a DER-encoded leaf certificate.
///
/// SAN URI `velcrux://identity/<name>` wins; failing that, the first
/// subject Common Name attribute. The result is passed through
/// [`validate_identity_name`] before returning, so a malformed, oversized,
/// or control-laden name fails closed rather than reaching authorization,
/// the state DB, or the logs.
fn extract_identity_name(leaf_der: &[u8]) -> Result<String> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::FromDer;

    let (_, cert) = X509Certificate::from_der(leaf_der).map_err(|_| {
        crate::error::ProtocolError::InvalidIdentity("leaf certificate parse failed")
    })?;

    // 1. Prefer the SAN URI velcrux://identity/<name>. First match wins.
    let mut name: Option<String> = None;
    'outer: for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in san.general_names.iter() {
                if let GeneralName::URI(uri) = gn {
                    if let Some(rest) = uri.strip_prefix(IDENTITY_URI_PREFIX) {
                        name = Some(rest.to_string());
                        break 'outer;
                    }
                }
            }
        }
    }

    // 2. Fall back to the subject Common Name.
    if name.is_none() {
        name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(|s| s.to_string());
    }

    let name = name.ok_or(crate::error::ProtocolError::InvalidIdentity(
        "no SAN identity URI and no Common Name",
    ))?;
    validate_identity_name(&name)?;
    Ok(name)
}

/// Validate an extracted identity name: non-empty, within
/// `MAX_IDENTITY_LEN` bytes so it always fits the AUTH_OK frame, and free
/// of control characters so it cannot corrupt logs or smuggle terminal
/// escapes (`SECURITY.md` §2, §9). Fails closed on any violation.
fn validate_identity_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(crate::error::ProtocolError::InvalidIdentity("empty identity name").into());
    }
    if name.len() > MAX_IDENTITY_LEN {
        return Err(crate::error::ProtocolError::InvalidIdentity("identity name too long").into());
    }
    if name.chars().any(char::is_control) {
        return Err(crate::error::ProtocolError::InvalidIdentity(
            "identity name contains control characters",
        )
        .into());
    }
    Ok(())
}

fn hex_fingerprint(der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(der);
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    /// Build a self-signed leaf certificate with the given Common Name and
    /// an optional SAN URI, returned as a single-element rustls chain.
    ///
    /// `identity_from_chain` only *extracts and validates the name* — the
    /// chain's trust is established earlier by rustls during the real
    /// handshake — so a self-signed fixture is sufficient and correct here.
    fn leaf_chain(cn: &str, san_uri: Option<&str>) -> Vec<Certificate> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        if let Some(uri) = san_uri {
            params.subject_alt_names = vec![SanType::URI(uri.to_string().try_into().unwrap())];
        }
        let key = KeyPair::generate().expect("keypair");
        let cert = params.self_signed(&key).expect("self-sign");
        let pem = cert.pem();
        rustls_pemfile::certs(&mut &pem.as_bytes()[..])
            .expect("parse leaf PEM")
            .into_iter()
            .map(Certificate)
            .collect()
    }

    #[test]
    fn san_uri_identity_wins_over_cn() {
        // Both a CN and a matching SAN identity URI are present; the SAN
        // URI must win (`SECURITY.md` §2 precedence).
        let chain = leaf_chain("common-name-should-lose", Some("velcrux://identity/alice"));
        let id = identity_from_chain(&chain).expect("identity");
        assert_eq!(id.name, "alice");
    }

    #[test]
    fn falls_back_to_common_name() {
        // No SAN URI → the subject Common Name is used.
        let chain = leaf_chain("bob", None);
        let id = identity_from_chain(&chain).expect("identity");
        assert_eq!(id.name, "bob");
    }

    #[test]
    fn non_velcrux_san_uri_falls_back_to_cn() {
        // A SAN URI that is not the velcrux identity prefix must be ignored,
        // falling back to the CN rather than adopting the foreign URI.
        let chain = leaf_chain("carol", Some("https://example.com/not-an-identity"));
        let id = identity_from_chain(&chain).expect("identity");
        assert_eq!(id.name, "carol");
    }

    #[test]
    fn empty_chain_is_rejected() {
        let chain: Vec<Certificate> = Vec::new();
        assert!(identity_from_chain(&chain).is_err());
    }

    #[test]
    fn single_cert_chain_issuer_equals_leaf_fingerprint() {
        let chain = leaf_chain("dave", Some("velcrux://identity/dave"));
        let id = identity_from_chain(&chain).expect("identity");
        // SHA-256 hex is 64 lowercase hex chars.
        assert_eq!(id.cert_fingerprint.len(), 64);
        assert!(id.cert_fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
        // Self-signed / single-cert chain: issuer fingerprint == leaf.
        assert_eq!(id.issuer_fingerprint, id.cert_fingerprint);
    }

    #[test]
    fn validate_identity_name_rejects_empty() {
        assert!(validate_identity_name("").is_err());
    }

    #[test]
    fn validate_identity_name_rejects_control_chars() {
        assert!(validate_identity_name("bad\nname").is_err());
        assert!(validate_identity_name("bad\tname").is_err());
        assert!(validate_identity_name("bad\0name").is_err());
    }

    #[test]
    fn validate_identity_name_rejects_oversize() {
        let big = "x".repeat(MAX_IDENTITY_LEN + 1);
        assert!(validate_identity_name(&big).is_err());
    }

    #[test]
    fn validate_identity_name_accepts_reasonable() {
        assert!(validate_identity_name("alice").is_ok());
        assert!(validate_identity_name(&"x".repeat(MAX_IDENTITY_LEN)).is_ok());
    }
}
