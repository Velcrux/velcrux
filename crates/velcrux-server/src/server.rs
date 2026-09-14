//! `velcruxd run` — accept loop and per-connection dispatch.
//!
//! M1: every accepted connection is handed to a `ServerConn` actor that
//! runs the M1 state machine (HELLO → PING/PONG → BYE). M2 will route
//! connections to per-transfer state.

use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::{Certificate, PrivateKey};
use serde::Deserialize;
use tracing::{info, warn};

use velcrux_core::auth::{Authenticator, Authorizer, FileAuthorizer, MtlsAuthenticator};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::session::{ServerConn, ServerStats};
use velcrux_core::transport::quic::{QuicConnection, ServerBuilder, TransportConfigTunables};
use velcrux_core::transport::Transport;

/// Subset of the full config (`OPERATIONS.md` §4) needed by the M1+M2 server.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub network: NetworkCfg,
    pub security: SecurityCfg,
    /// M2: storage root + staging dir. Same filesystem required so
    /// commit is an atomic `rename` (CLAUDE.md §1 #8, OPERATIONS.md §2).
    pub storage: StorageCfg,
}

#[derive(Debug, Deserialize)]
pub struct NetworkCfg {
    pub listen: String,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: String,
    #[serde(default = "default_keepalive")]
    pub keepalive: String,
}

#[derive(Debug, Deserialize)]
pub struct SecurityCfg {
    pub certificate: String,
    pub private_key: String,
    pub client_ca: String,
    /// Path to the authorization grants file (TOML; `SECURITY.md` §4).
    /// If absent, the server still authenticates clients over mTLS but
    /// grants them nothing: every operation is denied (deny-by-default).
    #[serde(default)]
    pub grants: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StorageCfg {
    pub root: String,
    pub staging: String,
    /// Absolute path to the M3 state DB (SQLite/WAL). Required
    /// for the M3 surface (STAT, LIST, CANCEL, RESUME). If absent,
    /// the M3 surface is disabled and the server runs in M2 mode.
    #[serde(default)]
    pub state_db: Option<String>,
}

fn default_idle_timeout() -> String {
    "60s".into()
}
fn default_keepalive() -> String {
    "15s".into()
}

/// Load TLS material, refuse to start on insecure permissions, build the
/// QUIC server, and run the accept loop forever.
pub async fn run(config_path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("read config {}", config_path.display()))?;
    let cfg: ServerConfig = toml::from_str(&raw).context("parse config")?;

    // Refuse to start if the key file is group/world-readable
    // (`SECURITY.md` §7).
    let key_path = std::path::Path::new(&cfg.security.private_key);
    if key_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(key_path)
                .with_context(|| format!("stat {}", key_path.display()))?
                .permissions();
            let mode = perms.mode();
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "private key {} is group/world readable (mode {:o}); refusing to start (`SECURITY.md` §7)",
                    key_path.display(),
                    mode
                );
            }
        }
    }

    let cert_pem = std::fs::read(&cfg.security.certificate)
        .with_context(|| format!("read cert {}", cfg.security.certificate))?;
    let key_pem = std::fs::read(&cfg.security.private_key)
        .with_context(|| format!("read key {}", cfg.security.private_key))?;
    let ca_pem = std::fs::read(&cfg.security.client_ca)
        .with_context(|| format!("read client CA {}", cfg.security.client_ca))?;

    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut &cert_pem[..])
        .map_err(|e| anyhow::anyhow!("parse server cert PEM: {e}"))?
        .into_iter()
        .map(Certificate)
        .collect();
    if certs.is_empty() {
        anyhow::bail!("no certificates in {}", cfg.security.certificate);
    }
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut &key_pem[..])
        .map_err(|e| anyhow::anyhow!("parse server key PEM: {e}"))?;
    let parsed_key = keys
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no PKCS#8 key in {}", cfg.security.private_key))?;
    let key_der = PrivateKey(parsed_key);

    let addr: std::net::SocketAddr = cfg
        .network
        .listen
        .parse()
        .with_context(|| format!("invalid listen address: {}", cfg.network.listen))?;

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);
    server_caps.set(Capability::CompressionZstd);
    server_caps.set(Capability::SparseFiles);
    server_caps.set(Capability::Symlinks);
    server_caps.set(Capability::Hardlinks);

    let tunables = parse_tunables(&cfg.network)?;
    let transport = ServerBuilder::new()
        .with_server_cert(certs, key_der)
        .with_client_ca_roots_pem(&ca_pem)?
        .with_tunables(tunables)
        .build(addr)?;
    let stats = Arc::new(ServerStats::default());
    info!(%addr, "velcruxd listening");

    // Construct the storage backend. M2 enforces same-filesystem for atomic
    // commit (OPERATIONS.md §2).
    let backend = velcrux_core::storage::LocalFilesystemBackend::new(
        std::path::PathBuf::from(&cfg.storage.root),
        std::path::PathBuf::from(&cfg.storage.staging),
    )
    .await
    .with_context(|| {
        format!(
            "storage backend init failed (root={}, staging={})",
            cfg.storage.root, cfg.storage.staging
        )
    })?;
    let backend = Arc::new(backend);

    // M3 state DB. The path must be absolute per ADR-005.
    use velcrux_core::state::StateStore as _;
    let state_store: Option<Arc<dyn velcrux_core::state::StateStore>> = match &cfg.storage.state_db
    {
        Some(path) => {
            let p = std::path::PathBuf::from(path);
            match velcrux_core::state::SqliteStateStore::new(&p) {
                Ok(s) => {
                    info!(state_db = %p.display(), "M3 state DB opened");
                    // Run commit-journal recovery (ADR-005).
                    match s.recover_commit_journal() {
                        Ok(actions) if !actions.is_empty() => {
                            info!(count = actions.len(), "commit journal recovery actions");
                            for a in actions {
                                if let velcrux_core::state::JournalRecovery::Finalize {
                                    transfer_id,
                                    file_id,
                                } = a
                                {
                                    let _ = s.mark_journal_committed(transfer_id, file_id);
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => warn!(error = %e, "journal recovery failed"),
                    }
                    Some(Arc::new(s))
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "state DB open failed (path={:?}): {} (ADR-005 requires absolute path)",
                        p,
                        e
                    ));
                }
            }
        }
        None => None,
    };

    // M4: authentication + authorization.
    //
    // Authentication is mTLS: the QUIC/TLS handshake already validated the
    // client certificate chain against the configured `client_ca`, so the
    // authenticator only confirms the extracted identity is present.
    //
    // Authorization is deny-by-default (`SECURITY.md` §4). A grants file
    // maps identities to path-prefix permissions; with no grants file the
    // server authenticates clients but authorizes nothing — every
    // operation is denied. A malformed grants file is a hard startup error
    // (fail closed) rather than a silent fall-back to deny-all, so an
    // operator never mistakes a broken config for an intentional lockdown.
    let authenticator: Arc<dyn Authenticator> = Arc::new(MtlsAuthenticator::new());
    let authorizer: Arc<dyn Authorizer> = match &cfg.security.grants {
        Some(path) => {
            let authz = FileAuthorizer::load(Path::new(path))
                .with_context(|| format!("load authorization grants file {path}"))?;
            info!(grants = %path, "authorization grants loaded");
            Arc::new(authz)
        }
        None => {
            warn!(
                "no authorization grants file configured (security.grants); \
                 all operations will be denied (deny-by-default, `SECURITY.md` §4)"
            );
            Arc::new(FileAuthorizer::new())
        }
    };

    let next_id = Arc::new(AtomicU64::new(1));
    loop {
        let conn = match transport.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let actor = ServerConn::with_state(
            server_caps,
            "velcruxd",
            Arc::clone(&stats),
            Arc::clone(&backend),
            state_store.clone(),
            Some(Arc::clone(&authenticator)),
            Some(Arc::clone(&authorizer)),
        );
        tokio::spawn(async move {
            let conn: QuicConnection = conn;
            match actor.run(&conn).await {
                Ok(state) => info!(conn_id = id, ?state, "connection finished"),
                Err(e) => warn!(conn_id = id, error = %e, "connection error"),
            }
        });
    }
}

fn parse_tunables(net: &NetworkCfg) -> Result<TransportConfigTunables> {
    Ok(TransportConfigTunables {
        receive_window: 384 * 1024 * 1024,
        stream_receive_window: 384 * 1024 * 1024,
        max_concurrent_streams: 32,
        idle_timeout: parse_duration(&net.idle_timeout)
            .with_context(|| format!("invalid idle_timeout: {}", net.idle_timeout))?,
        keepalive: parse_duration(&net.keepalive)
            .with_context(|| format!("invalid keepalive: {}", net.keepalive))?,
        initial_rtt: Duration::from_millis(150),
    })
}

/// Tiny duration parser: supports "<n>s" and "<n>ms". M2 will switch to a
/// real crate (e.g. `humantime` or `parse-duration`).
fn parse_duration(s: &str) -> Result<Duration> {
    if let Some(rest) = s.strip_suffix("ms") {
        let n: u64 = rest.parse().context("expected integer before 'ms'")?;
        return Ok(Duration::from_millis(n));
    }
    if let Some(rest) = s.strip_suffix('s') {
        let n: u64 = rest.parse().context("expected integer before 's'")?;
        return Ok(Duration::from_secs(n));
    }
    let n: u64 = s.parse().context("expected seconds (e.g. \"60s\")")?;
    Ok(Duration::from_secs(n))
}
