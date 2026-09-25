//! `velcruxd run` — accept loop and per-connection dispatch.
//!
//! Production-grade lifecycle:
//! - Accepts connections and hands to `ServerConn` actors.
//! - Exports Prometheus `/metrics` and `/healthz` HTTP server.
//! - Graceful drain on `SIGINT` / `SIGTERM`.
//! - Hot reload of authorization grants and certificates on `SIGHUP`.

use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::{Certificate, PrivateKey};
use tracing::{info, warn};

use velcrux_core::auth::{Authenticator, Authorizer, MtlsAuthenticator, Op};
use velcrux_core::error::{Result as CoreResult, VelcruxError};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::session::{ServerConn, ServerStats};
use velcrux_core::storage::VPath;
use velcrux_core::transport::identity::Identity;
use velcrux_core::transport::quic::{QuicConnection, ServerBuilder, TransportConfigTunables};
use velcrux_core::transport::Transport;

use crate::config::{parse_size_bytes, ServerConfig};

/// An authorizer wrapper that allows atomically swapping the underlying authorizer
/// at runtime without restarting the server or breaking active connections (e.g. on SIGHUP).
pub struct ReloadableAuthorizer {
    inner: RwLock<Arc<dyn Authorizer>>,
}

impl ReloadableAuthorizer {
    pub fn new(initial: Arc<dyn Authorizer>) -> Self {
        Self {
            inner: RwLock::new(initial),
        }
    }

    pub fn reload(&self, new_authz: Arc<dyn Authorizer>) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = new_authz;
        }
    }
}

impl Authorizer for ReloadableAuthorizer {
    fn check(&self, identity: &Identity, op: Op, raw_path: &str) -> CoreResult<VPath> {
        let authz = self
            .inner
            .read()
            .map_err(|_| VelcruxError::Internal("authorizer lock poisoned".into()))?
            .clone();
        authz.check(identity, op, raw_path)
    }

    fn granted_permissions(&self, identity: &Identity) -> velcrux_core::auth::PermSet {
        if let Ok(guard) = self.inner.read() {
            guard.granted_permissions(identity)
        } else {
            velcrux_core::auth::PermSet::default()
        }
    }
}

/// Load TLS material, refuse to start on insecure permissions, build the
/// QUIC server, spawn metrics exporter, and run the accept loop with signal handling.
pub async fn run(config_path: &Path) -> Result<()> {
    run_with_shutdown(config_path, std::future::pending()).await
}

/// Run server daemon with an external shutdown future, enabling graceful drain
/// coordination during production lifecycle tests and signal handling.
pub async fn run_with_shutdown<F>(config_path: &Path, external_shutdown: F) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let cfg = ServerConfig::load(config_path)?;

    let cert_pem = std::fs::read(&cfg.security.certificate)
        .with_context(|| format!("read cert {}", cfg.security.certificate))?;
    let key_pem = cfg.read_private_key_pem()?;
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

    let tunables = parse_tunables(&cfg)?;
    let transport = ServerBuilder::new()
        .with_server_cert(certs, key_der)
        .with_client_ca_roots_pem(&ca_pem)?
        .with_tunables(tunables)
        .build(addr)?;
    let stats = Arc::new(ServerStats::default());
    info!(%addr, "velcruxd listening");

    let metrics_shutdown = if let Some(metrics_listen) = &cfg.telemetry.metrics_listen {
        match crate::metrics::start_metrics_server(metrics_listen, Arc::clone(&stats)).await {
            Ok((_addr, tx)) => Some(tx),
            Err(e) => {
                warn!(error = %e, "failed to start metrics server");
                None
            }
        }
    } else {
        None
    };

    // Construct the storage backend. M2 enforces same-filesystem for atomic commit (OPERATIONS.md §2).
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

    // Optional LocalChunkStore for deduplication (Option D)
    let chunk_store: Option<Arc<velcrux_core::storage::LocalChunkStore>> =
        match &cfg.storage.chunk_store {
            Some(path) => {
                let p = std::path::PathBuf::from(path);
                match velcrux_core::storage::LocalChunkStore::new(&p).await {
                    Ok(cs) => {
                        info!(chunk_store = %p.display(), "LocalChunkStore initialized");
                        server_caps.set(Capability::DedupChunkStore);
                        Some(Arc::new(cs))
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to initialize chunk store");
                        None
                    }
                }
            }
            None => None,
        };

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
                                match a {
                                    velcrux_core::state::JournalRecovery::Finalize {
                                        transfer_id,
                                        file_id,
                                    } => {
                                        let _ = s.mark_journal_committed(transfer_id, file_id);
                                        if let Ok(mut r) = s.get_transfer(transfer_id) {
                                            r.status =
                                                velcrux_core::state::TransferStatus::Committed;
                                            let _ = s.update_transfer(&r);
                                        }
                                    }
                                    velcrux_core::state::JournalRecovery::LeavePending {
                                        transfer_id,
                                        ..
                                    } => {
                                        if let Ok(mut r) = s.get_transfer(transfer_id) {
                                            if r.status
                                                == velcrux_core::state::TransferStatus::Active
                                            {
                                                r.status =
                                                    velcrux_core::state::TransferStatus::Resumable;
                                                let _ = s.update_transfer(&r);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => warn!(error = %e, "journal recovery failed"),
                    }
                    if let Ok(count) = s.mark_active_transfers_resumable() {
                        if count > 0 {
                            info!(
                                count,
                                "recovered in-flight transfers from previous unclean shutdown as resumable"
                            );
                        }
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

    let authenticator: Arc<dyn Authenticator> = Arc::new(MtlsAuthenticator::new());
    let initial_authorizer: Arc<dyn Authorizer> = cfg
        .build_authorizer()
        .with_context(|| "failed to build authorizer from configuration")?;
    let reloadable_authorizer = Arc::new(ReloadableAuthorizer::new(initial_authorizer));
    let authorizer: Arc<dyn Authorizer> = Arc::clone(&reloadable_authorizer) as Arc<dyn Authorizer>;

    let next_id = Arc::new(AtomicU64::new(1));
    let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);

    // Signal listeners setup
    #[cfg(unix)]
    let mut sighup_stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("failed to register SIGHUP handler")?;

    #[cfg(unix)]
    let mut sigterm_stream =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to register SIGTERM handler")?;

    info!("velcruxd operational loop started");
    tokio::pin!(external_shutdown);

    loop {
        #[cfg(unix)]
        tokio::select! {
            _ = &mut external_shutdown => {
                info!("external shutdown signal received, starting graceful drain");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT (Ctrl+C) received, starting graceful drain");
                break;
            }
            _ = sigterm_stream.recv() => {
                info!("SIGTERM received, starting graceful drain (`OPERATIONS.md` §3)");
                break;
            }
            _ = sighup_stream.recv() => {
                info!("SIGHUP received, reloading configuration and authorization grants (`OPERATIONS.md` §3)");
                match ServerConfig::load(config_path) {
                    Ok(new_cfg) => {
                        match new_cfg.build_authorizer() {
                            Ok(new_authz) => {
                                reloadable_authorizer.reload(new_authz);
                                info!("configuration and grants reloaded successfully on SIGHUP");
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to build authorizer during SIGHUP reload");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to reload configuration on SIGHUP");
                    }
                }
            }
            accept_res = transport.accept() => {
                let conn = match accept_res {
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
                )
                .with_chunk_store(chunk_store.clone())
                .with_drain_signal(Some(drain_rx.clone()));
                tokio::spawn(async move {
                    let conn: QuicConnection = conn;
                    match actor.run(&conn).await {
                        Ok(state) => info!(conn_id = id, ?state, "connection finished"),
                        Err(e) => warn!(conn_id = id, error = %e, "connection error"),
                    }
                });
            }
        }

        #[cfg(not(unix))]
        tokio::select! {
            _ = &mut external_shutdown => {
                info!("external shutdown signal received, starting graceful drain");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT (Ctrl+C) received, starting graceful drain");
                break;
            }
            accept_res = transport.accept() => {
                let conn = match accept_res {
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
                )
                .with_chunk_store(chunk_store.clone())
                .with_drain_signal(Some(drain_rx.clone()));
                tokio::spawn(async move {
                    let conn: QuicConnection = conn;
                    match actor.run(&conn).await {
                        Ok(state) => info!(conn_id = id, ?state, "connection finished"),
                        Err(e) => warn!(conn_id = id, error = %e, "connection error"),
                    }
                });
            }
        }
    }

    info!("initiating graceful drain of active connections and transfers");
    let _ = drain_tx.send(true);

    if let Some(metrics_tx) = metrics_shutdown {
        let _ = metrics_tx.send(());
    }

    // Drain window (up to drain_timeout for in-flight tasks to checkpoint)
    let drain_timeout = cfg
        .network
        .drain_timeout
        .as_deref()
        .and_then(|s| parse_duration(s).ok())
        .unwrap_or(Duration::from_secs(5));

    let drain_start = std::time::Instant::now();
    while stats
        .transfers_active
        .load(std::sync::atomic::Ordering::Relaxed)
        > 0
    {
        if drain_start.elapsed() >= drain_timeout {
            warn!(?drain_timeout, "drain timeout exceeded, forcing exit");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Persist any remaining in-flight active transfers as resumable
    if let Some(store) = &state_store {
        if let Ok(count) = store.mark_active_transfers_resumable() {
            if count > 0 {
                info!(count, "persisted in-flight active transfers as resumable");
            }
        }
    }

    info!("velcruxd graceful shutdown complete");
    Ok(())
}

fn parse_tunables(cfg: &ServerConfig) -> Result<TransportConfigTunables> {
    let recv_win = parse_size_bytes(&cfg.quic.receive_window).unwrap_or(384 * 1024 * 1024);
    let stream_win = parse_size_bytes(&cfg.quic.stream_receive_window).unwrap_or(384 * 1024 * 1024);
    Ok(TransportConfigTunables {
        receive_window: recv_win,
        stream_receive_window: stream_win,
        max_concurrent_streams: cfg.quic.max_concurrent_streams,
        idle_timeout: parse_duration(&cfg.network.idle_timeout)
            .with_context(|| format!("invalid idle_timeout: {}", cfg.network.idle_timeout))?,
        keepalive: parse_duration(&cfg.network.keepalive)
            .with_context(|| format!("invalid keepalive: {}", cfg.network.keepalive))?,
        initial_rtt: parse_duration(&cfg.quic.initial_rtt).unwrap_or(Duration::from_millis(150)),
    })
}

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
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
