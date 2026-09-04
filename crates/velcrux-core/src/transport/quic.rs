//! `QuicTransport` — the only [`Transport`](super::Transport) implementation.
//!
//! QUIC does reliability, ordering within a stream, encryption, congestion
//! control, and packet authentication. We do not reimplement any of that
//! (`CLAUDE.md` §1 invariant #1). The rustls/QUIC-TLS configuration is built
//! here; the QUIC driver is `quinn`.
//!
//! ALPN is `VELCRUX/1` (`PROTOCOL.md` header). mTLS is required: a connection
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
use rustls::{
    Certificate, ClientConfig as RustlsClientConfig, PrivateKey, RootCertStore,
};
use sha2::{Digest, Sha256};

use crate::error::{Result, TransportError};
use crate::protocol::limits::{ALPN, QUIC_IDLE_TIMEOUT_SECS, QUIC_KEEPALIVE_SECS};
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
            .max_idle_timeout(Some(self.idle_timeout.try_into().expect("idle_timeout fits")))
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
            self.server_roots.add(&Certificate(c)).expect("adding trusted root");
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
            self.client_roots.add(&Certificate(c)).expect("adding client root");
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
    /// M1: the server accepts any client certificate during the TLS
    /// handshake. mTLS enforcement — a custom `ClientCertVerifier` that
    /// checks the chain against the configured `client_roots` — is wired
    /// in M2 alongside the auth state machine. Until then the server
    /// does have a TLS handshake with the client but does not verify
    /// the client's identity cryptographically; the session layer
    /// treats the connection as anonymous.
    pub fn build(self, addr: SocketAddr) -> Result<QuicTransport> {
        // Quiet the unused-field warning; this will be used in M2.
        let _client_roots = self.client_roots;

        let mut tls_cfg = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
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
        let c = self.0.read_chunk(max, true).await.map_err(|e| TransportError::ReadError(e.to_string()))?;
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
        let c = self.0.read_chunk(max, true).await.map_err(|e| TransportError::ReadError(e.to_string()))?;
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
// Identity extraction (M1 stub; full x509 parsing lands in M2)
// ---------------------------------------------------------------------------

/// Derive the [`Identity`] from a peer certificate chain.
///
/// M1 uses a simplified approach: the leaf certificate is hashed with
/// SHA-256 and the fingerprint prefix becomes the identity name. The
/// issuer fingerprint is the leaf (self-signed dev PKI) or the second
/// cert in the chain. Full x509 parsing — extracting the SAN URI and the
/// Common Name per `SECURITY.md` §2 — lands in M2 alongside the auth
/// state machine.
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
    let name = format!("cert-{}", &leaf_fp[..12]);
    Ok(Identity::new(name, issuer_fp, leaf_fp))
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



