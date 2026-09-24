//! `velcrux` client CLI. M1 surface: `velcrux ping velcrux://host:7443`.

#![forbid(unsafe_code)]

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use velcrux_core::session::ClientSession;
use velcrux_core::transport::quic::{ClientBuilder, ClientIdentity, QuicConnection};
use velcrux_core::transport::SharedTransport;

mod ping;

/// velcrux — high-throughput bulk transfer over QUIC.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to a PEM bundle of CA certificates used to verify the server.
    #[arg(long, env = "VELCRUX_CA", global = true)]
    ca: Option<PathBuf>,

    /// Path to the client certificate (PEM). Required for mTLS.
    #[arg(long, env = "VELCRUX_CERT", global = true)]
    cert: Option<PathBuf>,

    /// Path to the client private key (PEM, PKCS#8).
    #[arg(long, env = "VELCRUX_KEY", global = true)]
    key: Option<PathBuf>,

    /// Override the SNI hostname. Defaults to the host in the URL.
    #[arg(long, global = true)]
    sni: Option<String>,

    /// Log format: "text" (default) or "json".
    #[arg(long, default_value = "text", global = true)]
    log_format: String,

    /// Output machine-readable JSON on stdout.
    #[arg(long, global = true)]
    json: bool,

    /// Path to client state SQLite database.
    #[arg(long, env = "VELCRUX_STATE_DB", global = true)]
    state_db: Option<PathBuf>,

    /// Path to a TOML configuration file (defaults to ~/.velcrux/config.toml if present).
    #[arg(long, short, env = "VELCRUX_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Enable content-addressed chunk store deduplication (Option D).
    #[arg(long, global = true)]
    dedup: bool,

    /// Path to local chunk store directory for deduplication.
    #[arg(long, env = "VELCRUX_CHUNK_STORE", global = true)]
    chunk_store: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Open a session and round-trip a PING. The M1 exit test
    /// (`docs/ARCHITECTURE.md` §12).
    Ping {
        /// Target `velcrux://host:port` URL.
        url: String,
    },
    /// Upload a single local file to the server. M2.
    Upload {
        /// Local file to upload.
        local: PathBuf,
        /// Target `velcrux://host:port/path` URL.
        url: String,
    },
    /// Download a single remote file from the server. M2.
    Download {
        /// Source `velcrux://host:port/path` URL.
        url: String,
        /// Local destination path.
        local: PathBuf,
    },
    /// Resume a previously-interrupted transfer. M3.
    Resume {
        /// Transfer id (26-character ULID).
        transfer_id: String,
        /// Target server URL (e.g. `velcrux://host:port/`).
        #[arg(long, default_value = "velcrux://localhost:7443/")]
        server: String,
        /// Local file path (required if not found in client state store).
        #[arg(long)]
        local: Option<PathBuf>,
    },
    /// Cancel an in-progress transfer. M3.
    Cancel {
        /// Transfer id (26-character ULID).
        transfer_id: String,
        /// Target server URL (e.g. `velcrux://host:port/`).
        #[arg(long, default_value = "velcrux://localhost:7443/")]
        server: String,
    },
    /// Show state of a single transfer. M3.
    Stat {
        /// Transfer id (26-character ULID).
        transfer_id: String,
        /// Target server URL (e.g. `velcrux://host:port/`).
        #[arg(long, default_value = "velcrux://localhost:7443/")]
        server: String,
    },
    /// List transfers by URL prefix. M3.
    List {
        /// URL prefix, e.g. `velcrux://host:7443/data/`.
        url_prefix: String,
    },
    /// Synchronize a directory tree incrementally (M9).
    Sync {
        /// Source directory or URL.
        source: String,
        /// Destination directory or URL.
        destination: String,
        /// Calculate changes and print summary without modifying destination.
        #[arg(long)]
        dry_run: bool,
        /// Delete extraneous destination files after all commits succeed.
        #[arg(long)]
        delete_after: bool,
        /// Alias for --delete-after.
        #[arg(long)]
        delete: bool,
        /// Use content-defined chunking (FastCDC) instead of fixed chunking.
        #[arg(long)]
        cdc: bool,
        /// Enable content-addressed chunk store deduplication.
        #[arg(long)]
        dedup: bool,
        /// Optional path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
    },
    /// Generate shell completion script (bash, zsh, fish, powershell, elvish).
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
}

fn init_tracing(format: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,velcrux_core=debug"));
    if format == "json" {
        let _ = fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .json()
            .try_init();
    } else {
        let _ = fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init();
    }
}

fn read_file(path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn parse_url(s: &str) -> anyhow::Result<SocketAddr> {
    // `url::Url` doesn't accept unknown schemes in non-special contexts, so
    // we parse the URL by hand for M1. Format: `velcrux://host[:port][/path]`.
    let stripped = s
        .strip_prefix("velcrux://")
        .context("URL must start with velcrux://")?;
    let hostport = stripped.split('/').next().unwrap_or(stripped);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().context("invalid port")?;
            (h, port)
        }
        None => (hostport, 7443u16),
    };
    if host.is_empty() {
        anyhow::bail!("URL has no host");
    }
    // Resolve via ToSocketAddrs so `localhost` works.
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .context("invalid host:port")?
        .collect();
    addrs
        .iter()
        .copied()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.into_iter().next())
        .context("no addresses resolved for host")
}

/// Parse a `velcrux://host:port/path` URL into the host:port `SocketAddr`
/// and the URL-decoded path component.
fn parse_url_with_path(s: &str) -> anyhow::Result<(SocketAddr, String)> {
    let stripped = s
        .strip_prefix("velcrux://")
        .context("URL must start with velcrux://")?;
    let (hostport, path) = match stripped.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (stripped, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().context("invalid port")?;
            (h, port)
        }
        None => (hostport, 7443u16),
    };
    if host.is_empty() {
        anyhow::bail!("URL has no host");
    }
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .context("invalid host:port")?
        .collect();
    let addr = addrs
        .iter()
        .copied()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.into_iter().next())
        .context("no addresses resolved for host")?;
    Ok((addr, path))
}

fn build_transport(cli: &Cli) -> anyhow::Result<SharedTransport> {
    let ca_path = cli
        .ca
        .as_ref()
        .context("--ca is required (no insecure mode is supported; see SECURITY.md §3)")?;
    let ca_pem = read_file(ca_path)?;
    let mut builder = ClientBuilder::new().with_server_roots_pem(&ca_pem)?;

    if let (Some(cert), Some(key)) = (cli.cert.as_ref(), cli.key.as_ref()) {
        let cert_pem = read_file(cert)?;
        let key_pem = read_file(key)?;
        let certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &cert_pem[..])
            .map_err(|e| anyhow::anyhow!("parsing client cert PEM: {e}"))?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut &key_pem[..])
            .map_err(|e| anyhow::anyhow!("parsing client key PEM: {e}"))?;
        let key = keys
            .pop()
            .ok_or_else(|| anyhow::anyhow!("no PKCS#8 key in {}", key.display()))?;
        let id = ClientIdentity::from_der(certs, key.clone());
        builder = builder.with_client_identity(id);
    }

    let transport: Arc<dyn velcrux_core::transport::Transport<Conn = QuicConnection>> =
        Arc::new(builder.build()?);
    Ok(transport)
}

fn open_client_state_store(cli: &Cli) -> Option<Arc<dyn velcrux_core::state::StateStore>> {
    if let Some(path) = &cli.state_db {
        if let Ok(store) = velcrux_core::state::SqliteStateStore::new(path) {
            return Some(Arc::new(store));
        }
    } else if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home).join(".velcrux").join("client.db");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(store) = velcrux_core::state::SqliteStateStore::new(&path) {
            return Some(Arc::new(store));
        }
    }
    None
}

async fn open_client_session(
    conn: &dyn velcrux_core::transport::Connection,
    cli: &Cli,
) -> anyhow::Result<ClientSession> {
    let (send, recv) = conn.open_bi().await?;
    let mut caps = velcrux_core::protocol::message::Hello::default_client().capabilities;
    if cli.dedup || cli.chunk_store.is_some() {
        caps.set(velcrux_core::protocol::capabilities::Capability::DedupChunkStore);
    }
    let session =
        ClientSession::from_handshake_parts_with_capabilities(send, recv, Some(caps)).await?;
    Ok(session)
}

async fn open_client_chunk_store(cli: &Cli) -> Option<Arc<velcrux_core::storage::LocalChunkStore>> {
    let path = if let Some(ref p) = cli.chunk_store {
        Some(p.clone())
    } else if cli.dedup {
        if let Some(home) = std::env::var_os("HOME") {
            Some(PathBuf::from(home).join(".velcrux").join("chunks"))
        } else {
            Some(PathBuf::from(".velcrux-chunks"))
        }
    } else {
        None
    };

    if let Some(p) = path {
        match velcrux_core::storage::LocalChunkStore::new(&p).await {
            Ok(cs) => Some(Arc::new(cs)),
            Err(e) => {
                tracing::warn!(error = %e, path = %p.display(), "failed to initialize client chunk store");
                None
            }
        }
    } else {
        None
    }
}

fn cli_log_json(cli: &Cli) -> bool {
    cli.json || cli.log_format == "json" || std::env::var("VELCRUX_OUTPUT_JSON").is_ok()
}

fn get_sni(cli: &Cli, url: &str) -> String {
    cli.sni.clone().unwrap_or_else(|| {
        url.split("://")
            .nth(1)
            .unwrap_or("localhost")
            .split(':')
            .next()
            .unwrap_or("localhost")
            .to_string()
    })
}

#[derive(Debug, serde::Deserialize, Default)]
struct FileClientConfig {
    ca: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    sni: Option<String>,
    log_format: Option<String>,
    json: Option<bool>,
    state_db: Option<PathBuf>,
    dedup: Option<bool>,
    chunk_store: Option<PathBuf>,
}

fn load_client_config(cli: &mut Cli) {
    let config_path = cli.config.clone().or_else(|| {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".velcrux").join("config.toml"))
    });

    if let Some(path) = config_path {
        if path.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(file_cfg) = toml::from_str::<FileClientConfig>(&raw) {
                    if cli.ca.is_none() {
                        cli.ca = file_cfg.ca;
                    }
                    if cli.cert.is_none() {
                        cli.cert = file_cfg.cert;
                    }
                    if cli.key.is_none() {
                        cli.key = file_cfg.key;
                    }
                    if cli.sni.is_none() {
                        cli.sni = file_cfg.sni;
                    }
                    if cli.state_db.is_none() {
                        cli.state_db = file_cfg.state_db;
                    }
                    if cli.chunk_store.is_none() {
                        cli.chunk_store = file_cfg.chunk_store;
                    }
                    if !cli.dedup {
                        if let Some(d) = file_cfg.dedup {
                            cli.dedup = d;
                        }
                    }
                    if cli.log_format == "text" {
                        if let Some(fmt) = file_cfg.log_format {
                            cli.log_format = fmt;
                        }
                    }
                    if !cli.json {
                        if let Some(j) = file_cfg.json {
                            cli.json = j;
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    load_client_config(&mut cli);
    init_tracing(&cli.log_format);

    match &cli.cmd {
        Cmd::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(*shell, &mut cmd, "velcrux", &mut std::io::stdout());
            return Ok(());
        }
        Cmd::Ping { url } => {
            let addr = parse_url(url)?;
            let sni = get_sni(&cli, url);
            let transport = build_transport(&cli)?;
            info!(%addr, %sni, "connecting");
            let mut session = ClientSession::connect(transport, addr, &sni).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            let rtt_ms = ping::ping(&mut session).await?;
            println!("PONG rtt={rtt_ms}ms");
            session.bye().await.ok();
        }
        Cmd::Upload { local, url } => {
            let (addr, path) = parse_url_with_path(url)?;
            let sni = get_sni(&cli, url);
            let transport = build_transport(&cli)?;
            info!(%addr, %sni, ?path, "connecting");
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            let store = open_client_state_store(&cli);
            run_upload(&cli, &conn, &mut session, local, &path, &store).await?;
        }
        Cmd::Download { url, local } => {
            let (addr, path) = parse_url_with_path(url)?;
            let sni = get_sni(&cli, url);
            let transport = build_transport(&cli)?;
            info!(%addr, %sni, ?path, "connecting");
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            run_download(&cli, &conn, &mut session, local, &path).await?;
        }
        Cmd::Resume {
            transfer_id,
            server,
            local,
        } => {
            let (addr, _) = parse_url_with_path(server)?;
            let sni = get_sni(&cli, server);
            let transport = build_transport(&cli)?;
            info!(%addr, %sni, "connecting for resume");
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            let store = open_client_state_store(&cli);
            run_resume(&cli, &conn, &mut session, transfer_id, local, &store).await?;
        }
        Cmd::Cancel {
            transfer_id,
            server,
        } => {
            let (addr, _) = parse_url_with_path(server)?;
            let sni = get_sni(&cli, server);
            let transport = build_transport(&cli)?;
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            run_cancel(&cli, &mut session, transfer_id).await?;
        }
        Cmd::Stat {
            transfer_id,
            server,
        } => {
            let (addr, _) = parse_url_with_path(server)?;
            let sni = get_sni(&cli, server);
            let transport = build_transport(&cli)?;
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            run_stat(&cli, &mut session, transfer_id).await?;
        }
        Cmd::List { url_prefix } => {
            let (addr, path) = parse_url_with_path(url_prefix)?;
            let sni = get_sni(&cli, url_prefix);
            let transport = build_transport(&cli)?;
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            let clean_prefix = path.trim_start_matches('/').to_string();
            run_list(&cli, &mut session, &clean_prefix).await?;
        }
        Cmd::Sync {
            source,
            destination,
            dry_run,
            delete_after,
            delete,
            cdc,
            dedup,
            chunk_store,
        } => {
            run_sync(
                &cli,
                source,
                destination,
                *dry_run,
                *delete_after,
                *delete,
                *cdc,
                *dedup,
                chunk_store,
            )
            .await?;
        }
    }
    Ok(())
}

async fn upload_file_stream(
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    store: &Option<Arc<dyn velcrux_core::state::StateStore>>,
    local: &PathBuf,
    remote_path: &str,
    show_progress: bool,
    cli: &Cli,
) -> anyhow::Result<(velcrux_core::util::TransferId, velcrux_core::Hash, u64)> {
    use velcrux_core::protocol::message::{
        Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    };
    use velcrux_core::session::encode_message;
    use velcrux_core::state::ChunkBitmap;

    let file_size = std::fs::metadata(local)
        .with_context(|| format!("stat {local:?}"))?
        .len();
    let expected_hash =
        velcrux_core::sync::compute_file_hash(local).with_context(|| format!("hash {local:?}"))?;

    let idempotency_key = velcrux_core::util::TransferId::generate().to_string();
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: local.display().to_string(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: idempotency_key.clone(),
        file_size,
        file_hash: expected_hash,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }
    let created = TransferCreated::decode(frame.payload)?;
    let frame = session.recv_frame().await?;
    let mut initial_bitmap = ChunkBitmap::new();
    let plan = if frame.type_byte == velcrux_core::protocol::message::INVENTORY_HINT {
        use velcrux_core::protocol::message::{ChunkQuery, ChunkResponse, InventoryHint};
        use velcrux_core::sync::{BloomFilter, RleBitmap};

        let hint = InventoryHint::decode(frame.payload)?;
        let _bloom = BloomFilter::from_bytes(&hint.bitset, hint.filter_bits, hint.num_hashes)
            .map_err(|e| anyhow::anyhow!("invalid bloom filter: {e}"))?;

        let mut file = std::fs::File::open(local)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut chunk_hashes = Vec::new();
        let mut chunk_indices = Vec::new();
        let mut offset = 0u64;
        let mut chunk_idx = 0u64;
        use std::io::Read;
        while offset < file_size {
            let to_read = ((file_size - offset).min(64 * 1024)) as usize;
            file.read_exact(&mut buf[..to_read])?;
            let h = velcrux_core::Hash::of(&buf[..to_read]);
            chunk_hashes.push(h);
            chunk_indices.push((chunk_idx, to_read as u64));
            offset += to_read as u64;
            chunk_idx += 1;
        }

        let query = ChunkQuery {
            transfer_id: created.transfer_id,
            query_seq: 1,
            chunk_hashes,
        };
        let q_buf = bytes::Bytes::from(encode_message(&Message::ChunkQuery(query), 0)?);
        session.send_mut().write_all(q_buf).await?;

        let resp_frame = session.recv_frame().await?;
        if resp_frame.type_byte != velcrux_core::protocol::message::CHUNK_RESPONSE {
            anyhow::bail!(
                "expected CHUNK_RESPONSE, got 0x{:02x}",
                resp_frame.type_byte
            );
        }
        let resp = ChunkResponse::decode(resp_frame.payload)?;
        let rle = RleBitmap::decode(&resp.rle_bitmap, resp.total_chunks)
            .map_err(|e| anyhow::anyhow!("invalid rle bitmap: {e}"))?;

        for (i, &(c_idx, len)) in chunk_indices.iter().enumerate() {
            if rle.get(i) == Some(true) {
                initial_bitmap.mark_complete(c_idx, len);
            }
        }

        let plan_frame = session.recv_frame().await?;
        if plan_frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
            anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", plan_frame.type_byte);
        }
        TransferPlan::decode(plan_frame.payload)?
    } else if frame.type_byte == velcrux_core::protocol::message::TRANSFER_PLAN {
        TransferPlan::decode(frame.payload)?
    } else {
        anyhow::bail!(
            "expected TRANSFER_PLAN or INVENTORY_HINT, got 0x{:02x}",
            frame.type_byte
        );
    };

    if plan.bytes_to_transfer == 0 {
        use velcrux_core::protocol::message::{Commit, Verify, VerifyResult};
        let begin = TransferBegin {
            transfer_id: created.transfer_id,
        };
        session
            .send_mut()
            .write_all(bytes::Bytes::from(encode_message(
                &Message::TransferBegin(begin),
                0,
            )?))
            .await?;

        let verify = Verify {
            transfer_id: created.transfer_id,
            expected_hash,
        };
        session
            .send_mut()
            .write_all(bytes::Bytes::from(encode_message(
                &Message::Verify(verify),
                0,
            )?))
            .await?;

        let frame = session.recv_frame().await?;
        if frame.type_byte != velcrux_core::protocol::message::VERIFY_RESULT {
            anyhow::bail!("expected VERIFY_RESULT, got 0x{:02x}", frame.type_byte);
        }
        let vr = VerifyResult::decode(frame.payload)?;
        if !vr.ok {
            anyhow::bail!("server reported verify mismatch on skip");
        }

        let commit = Commit {
            transfer_id: created.transfer_id,
        };
        session
            .send_mut()
            .write_all(bytes::Bytes::from(encode_message(
                &Message::Commit(commit),
                0,
            )?))
            .await?;

        let frame = session.recv_frame().await?;
        if frame.type_byte != velcrux_core::protocol::message::COMMITTED {
            anyhow::bail!("expected COMMITTED, got 0x{:02x}", frame.type_byte);
        }

        if let Some(cs) = open_client_chunk_store(cli).await {
            let params =
                velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
            let _ = cs.ingest_file_sync(local, velcrux_core::chunking::ChunkMode::Fixed, params);
        }

        return Ok((created.transfer_id, expected_hash, 0));
    }

    let begin = TransferBegin {
        transfer_id: created.transfer_id,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let is_json = cli_log_json(cli);
    let bytes_to_transfer = plan.bytes_to_transfer;
    let (progress_tx, progress_handle) = if show_progress && !is_json {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(100);
        let tid_str = created.transfer_id.to_string();
        let handle = tokio::spawn(async move {
            let mut transferred = 0u64;
            let mut last_print = std::time::Instant::now();
            let start_time = std::time::Instant::now();
            while let Some(delta) = rx.recv().await {
                transferred = transferred.saturating_add(delta);
                if last_print.elapsed() >= std::time::Duration::from_millis(200)
                    || transferred >= bytes_to_transfer
                {
                    let elapsed_secs = start_time.elapsed().as_secs_f64();
                    let rate = if elapsed_secs > 0.0 {
                        transferred as f64 / elapsed_secs
                    } else {
                        0.0
                    };
                    let pct = if bytes_to_transfer > 0 {
                        (transferred as f64 / bytes_to_transfer as f64) * 100.0
                    } else {
                        100.0
                    };
                    eprint!(
                        "\r[{}] {} / {} ({:.1}%) — {}/s",
                        tid_str,
                        format_bytes(transferred),
                        format_bytes(bytes_to_transfer),
                        pct,
                        format_bytes(rate as u64)
                    );
                    last_print = std::time::Instant::now();
                }
            }
            if transferred > 0 {
                eprintln!();
            }
        });
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };

    let mut cfg = velcrux_core::PipelineConfig::default();
    if !initial_bitmap.is_empty() {
        cfg.chunk_mode = velcrux_core::chunking::ChunkMode::Fixed;
        cfg.chunk_params =
            velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
    }
    let (send_half, recv_half) = session.stream_halves_mut();
    let computed = velcrux_core::client_upload_stream(
        conn,
        send_half,
        recv_half,
        store.clone(),
        created.transfer_id,
        &idempotency_key,
        local.clone(),
        remote_path.trim_start_matches('/'),
        file_size,
        expected_hash,
        initial_bitmap,
        cfg,
        progress_tx,
    )
    .await?;

    if let Some(h) = progress_handle {
        let _ = h.await;
    }

    if let Some(cs) = open_client_chunk_store(cli).await {
        let params =
            velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
        let _ = cs.ingest_file_sync(local, velcrux_core::chunking::ChunkMode::Fixed, params);
    }

    Ok((created.transfer_id, computed, plan.bytes_to_transfer))
}

async fn run_upload(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    local: &PathBuf,
    url_path: &str,
    store: &Option<Arc<dyn velcrux_core::state::StateStore>>,
) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let (tid, computed, bytes_transferred) =
        upload_file_stream(conn, session, store, local, url_path, true, cli).await?;
    let file_size = std::fs::metadata(local)
        .map(|m| m.len())
        .unwrap_or(bytes_transferred);

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "transfer_complete",
            "op": "upload",
            "transfer_id": tid.to_string(),
            "file_size": file_size,
            "bytes_transferred": bytes_transferred,
            "bytes_completed": bytes_transferred,
            "file_hash": computed.to_string(),
            "status": "committed"
        });
        println!("{out}");
    } else {
        println!("transfer_id: {tid}");
        println!(
            "upload: committed {} bytes (transferred {} bytes); server hash matches: true",
            file_size, bytes_transferred
        );
    }
    session.bye().await.ok();
    Ok(())
}

async fn run_resume(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    transfer_id_str: &str,
    local_override: &Option<PathBuf>,
    store: &Option<Arc<dyn velcrux_core::state::StateStore>>,
) -> anyhow::Result<()> {
    use std::io::Read;
    use velcrux_core::protocol::message::{Message, Resume, ResumeState, TransferBegin};
    use velcrux_core::session::encode_message;
    use velcrux_core::state::ChunkBitmap;

    let transfer_id = velcrux_core::util::TransferId::from_string(transfer_id_str)
        .ok_or_else(|| anyhow::anyhow!("invalid transfer id: {transfer_id_str}"))?;

    let resume_req = Resume {
        transfer_id,
        idempotency_key: String::new(),
    };
    let buf = bytes::Bytes::from(encode_message(&Message::Resume(resume_req), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::RESUME_STATE {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected RESUME_STATE, got 0x{:02x}", frame.type_byte);
    }
    let resume_state = ResumeState::decode(frame.payload)?;

    let local_path: PathBuf = if let Some(p) = local_override {
        p.clone()
    } else if let Some(s) = store {
        if let Ok(rec) = s.get_transfer(transfer_id) {
            PathBuf::from(rec.local_path)
        } else {
            let base = std::path::Path::new(&resume_state.staging_relpath)
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("download"));
            base
        }
    } else {
        let base = std::path::Path::new(&resume_state.staging_relpath)
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("download"));
        base
    };

    if !local_path.exists() {
        anyhow::bail!(
            "local file not found at {}: please specify --local <path>",
            local_path.display()
        );
    }

    let file_size = std::fs::metadata(&local_path)
        .with_context(|| format!("stat {local_path:?}"))?
        .len();
    if file_size != resume_state.file_size {
        anyhow::bail!(
            "local file size ({file_size}) does not match remote transfer size ({})",
            resume_state.file_size
        );
    }

    let expected_hash = {
        let mut f =
            std::fs::File::open(&local_path).with_context(|| format!("open {local_path:?}"))?;
        let mut h = velcrux_core::HashHasher::new();
        let mut buf = vec![0u8; 2 * 1024 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .with_context(|| format!("read {local_path:?}"))?;
            if n == 0 {
                break;
            }
            h.feed(&buf[..n]);
        }
        h.finalize()
    };
    if expected_hash != resume_state.file_hash {
        anyhow::bail!("local file hash does not match transfer file hash");
    }

    let begin = TransferBegin { transfer_id };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let bitmap = ChunkBitmap::from_sorted_indices(
        &resume_state.completed_chunks,
        resume_state.bytes_completed,
    );

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<u64>(100);
    let tid_str = transfer_id.to_string();
    let is_json = cli_log_json(cli);
    let progress_handle = tokio::spawn(async move {
        let mut transferred = 0u64;
        let mut last_print = std::time::Instant::now();
        let start_time = std::time::Instant::now();
        while let Some(delta) = progress_rx.recv().await {
            transferred = transferred.saturating_add(delta);
            if !is_json
                && (last_print.elapsed() >= std::time::Duration::from_millis(200)
                    || transferred >= file_size)
            {
                let elapsed_secs = start_time.elapsed().as_secs_f64();
                let rate = if elapsed_secs > 0.0 {
                    transferred as f64 / elapsed_secs
                } else {
                    0.0
                };
                let pct = if file_size > 0 {
                    (transferred as f64 / file_size as f64) * 100.0
                } else {
                    100.0
                };
                eprint!(
                    "\r[{}] {} / {} ({:.1}%) — {}/s",
                    tid_str,
                    format_bytes(transferred),
                    format_bytes(file_size),
                    pct,
                    format_bytes(rate as u64)
                );
                last_print = std::time::Instant::now();
            }
        }
        if !is_json && transferred > 0 {
            eprintln!();
        }
    });

    let cfg = velcrux_core::PipelineConfig::default();
    let (send_half, recv_half) = session.stream_halves_mut();
    let computed = velcrux_core::client_upload_stream(
        conn,
        send_half,
        recv_half,
        store.clone(),
        transfer_id,
        "",
        local_path,
        &resume_state.staging_relpath,
        file_size,
        expected_hash,
        bitmap,
        cfg,
        Some(progress_tx),
    )
    .await?;

    let _ = progress_handle.await;

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "transfer_complete",
            "op": "resume",
            "transfer_id": transfer_id.to_string(),
            "file_size": file_size,
            "file_hash": computed.to_string(),
            "status": "committed"
        });
        println!("{out}");
    } else {
        println!("transfer_id: {}", transfer_id);
        println!(
            "resume: committed {} bytes; server hash matches: {}",
            file_size,
            computed == expected_hash
        );
    }
    Ok(())
}

async fn run_stat(
    cli: &Cli,
    session: &mut ClientSession,
    transfer_id_str: &str,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Message, StatQuery, StatResult};
    use velcrux_core::session::encode_message;

    let transfer_id = velcrux_core::util::TransferId::from_string(transfer_id_str)
        .ok_or_else(|| anyhow::anyhow!("invalid transfer id: {transfer_id_str}"))?;
    let q = StatQuery { transfer_id };
    let buf = bytes::Bytes::from(encode_message(&Message::Stat(q), 0)?);
    session.send_mut().write_all(buf).await?;
    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::STAT_RESULT {
        anyhow::bail!("expected STAT_RESULT, got 0x{:02x}", frame.type_byte);
    }
    let r = StatResult::decode(frame.payload)?;
    if !r.found {
        anyhow::bail!("transfer not found: {}", transfer_id_str);
    }
    if cli_log_json(cli) {
        let obj = serde_json::json!({
            "v": 1,
            "event": "stat",
            "transfer_id": r.transfer_id.to_string(),
            "status": r.status,
            "direction": r.direction,
            "remote_path": r.remote_path,
            "file_size": r.file_size,
            "bytes_completed": r.bytes_completed,
            "verified_up_to": r.verified_up_to,
            "created_ms": r.created_ms,
            "updated_ms": r.updated_ms,
        });
        println!("{obj}");
    } else {
        println!(
            "{:<26}  {:<10}  {:<10}  {:>10}  {:>10}  {}",
            r.transfer_id, r.status, r.direction, r.file_size, r.bytes_completed, r.remote_path
        );
    }
    Ok(())
}

async fn run_list(cli: &Cli, session: &mut ClientSession, url_prefix: &str) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{ListQuery, ListResult, Message};
    use velcrux_core::session::encode_message;

    let q = ListQuery {
        url_prefix: url_prefix.to_string(),
    };
    let buf = bytes::Bytes::from(encode_message(&Message::List(q), 0)?);
    session.send_mut().write_all(buf).await?;
    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::LIST_RESULT {
        anyhow::bail!("expected LIST_RESULT, got 0x{:02x}", frame.type_byte);
    }
    let r = ListResult::decode(frame.payload)?;
    if cli_log_json(cli) {
        let arr: Vec<_> = r
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "v": 1,
                    "event": "stat",
                    "transfer_id": e.transfer_id.to_string(),
                    "status": e.status,
                    "direction": e.direction,
                    "remote_path": e.remote_path,
                    "file_size": e.file_size,
                    "bytes_completed": e.bytes_completed,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(arr));
    } else if r.entries.is_empty() {
        println!("(no transfers match {url_prefix})");
    } else {
        for e in &r.entries {
            println!(
                "{:<26}  {:<10}  {:>10}  {}",
                e.transfer_id, e.status, e.file_size, e.remote_path
            );
        }
    }
    Ok(())
}

async fn run_cancel(
    cli: &Cli,
    session: &mut ClientSession,
    transfer_id_str: &str,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::error::ErrorCode;
    use velcrux_core::protocol::message::{Cancel, Message};
    use velcrux_core::session::encode_message;

    let transfer_id = velcrux_core::util::TransferId::from_string(transfer_id_str)
        .ok_or_else(|| anyhow::anyhow!("invalid transfer id: {transfer_id_str}"))?;
    let c = Cancel {
        transfer_id,
        reason_code: ErrorCode::TransferCancelled.to_wire(),
    };
    let buf = bytes::Bytes::from(encode_message(&Message::Cancel(c), 0)?);
    session.send_mut().write_all(buf).await?;
    session.bye().await.ok();
    if cli_log_json(cli) {
        let obj = serde_json::json!({
            "v": 1,
            "event": "cancel",
            "transfer_id": transfer_id_str,
            "status": "cancelled",
        });
        println!("{obj}");
    } else {
        println!("cancel requested: {transfer_id_str}");
    }
    Ok(())
}

async fn download_file_stream(
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    remote_path: &str,
    local: &PathBuf,
    show_progress: bool,
    cli: &Cli,
) -> anyhow::Result<(velcrux_core::util::TransferId, velcrux_core::Hash, u64)> {
    use velcrux_core::protocol::message::{
        Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    };
    use velcrux_core::session::encode_message;

    let create = TransferCreate {
        op: TransferOp::Download,
        src_path: "".into(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }
    let created = TransferCreated::decode(frame.payload)?;
    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
        anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", frame.type_byte);
    }
    let mut plan = TransferPlan::decode(frame.payload)?;

    let mut staging_prepopulated = false;
    let client_cs = open_client_chunk_store(cli).await;
    let local_exists = local.is_file();

    // Check if local file or client chunk store can participate in deduplication/delta download
    if local_exists || client_cs.is_some() {
        use velcrux_core::protocol::message::{ChunkQuery, ChunkResponse, InventoryHint};
        use velcrux_core::sync::RleBitmap;

        let inv_opt = if local_exists {
            velcrux_core::sync::LocalInventory::from_file(
                local,
                velcrux_core::chunking::ChunkMode::Fixed,
                velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap(),
                64 * 1024,
            )
            .ok()
        } else {
            None
        };

        if inv_opt.is_some() || client_cs.is_some() {
            let bloom = match (&inv_opt, &client_cs) {
                (Some(inv), Some(cs)) => {
                    let mut b = cs.bloom_filter();
                    for h in inv.chunk_hashes() {
                        b.insert(h);
                    }
                    b
                }
                (Some(inv), None) => inv.create_bloom_filter(0.01),
                (None, Some(cs)) => cs.bloom_filter(),
                (None, None) => unreachable!(),
            };

            let hint = InventoryHint {
                transfer_id: created.transfer_id,
                filter_bits: bloom.num_bits(),
                num_hashes: bloom.num_hashes(),
                bitset: bytes::Bytes::copy_from_slice(bloom.bitset_bytes()),
            };
            session
                .send_mut()
                .write_all(bytes::Bytes::from(encode_message(
                    &Message::InventoryHint(hint),
                    0,
                )?))
                .await?;

            let q_frame = session.recv_frame().await?;
            if q_frame.type_byte == velcrux_core::protocol::message::CHUNK_QUERY {
                let query = ChunkQuery::decode(q_frame.payload)?;
                let mut have_bits = Vec::with_capacity(query.chunk_hashes.len());
                let mut matching_chunks = Vec::new();
                let mut matching_store_chunks = Vec::new();
                for (idx, h) in query.chunk_hashes.iter().enumerate() {
                    let dst_off = idx as u64 * (64 * 1024);
                    let chunk_len = (plan.bytes_total - dst_off).min(64 * 1024);
                    if let Some(extent) = inv_opt.as_ref().and_then(|inv| inv.lookup(h)) {
                        have_bits.push(true);
                        matching_chunks.push((dst_off, extent.offset, extent.length));
                    } else if client_cs
                        .as_ref()
                        .map(|cs| cs.contains_sync(h))
                        .unwrap_or(false)
                    {
                        have_bits.push(true);
                        matching_store_chunks.push((dst_off, *h, chunk_len));
                    } else {
                        have_bits.push(false);
                    }
                }
                let rle = RleBitmap::from_bits(&have_bits);
                let resp = ChunkResponse {
                    transfer_id: created.transfer_id,
                    query_seq: query.query_seq,
                    total_chunks: rle.total_chunks(),
                    have_count: rle.have_count(),
                    rle_bitmap: rle.encode(),
                };
                session
                    .send_mut()
                    .write_all(bytes::Bytes::from(encode_message(
                        &Message::ChunkResponse(resp),
                        0,
                    )?))
                    .await?;

                // Pre-stage matching chunks into staging file on client
                let staging_path = {
                    let mut p = local.clone().into_os_string();
                    p.push(".velcrux-partial");
                    std::path::PathBuf::from(p)
                };
                if let Some(parent) = staging_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let mut staging_f = std::fs::OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .truncate(true)
                    .open(&staging_path)?;
                staging_f.set_len(plan.bytes_total)?;

                // 1. Copy from existing local file
                if local_exists && !matching_chunks.is_empty() {
                    if let Ok(mut src_f) = std::fs::File::open(local) {
                        use std::io::{Read, Seek, SeekFrom, Write};
                        let mut copy_buf = [0u8; 64 * 1024];
                        for (dst_offset, src_offset, len) in matching_chunks {
                            src_f.seek(SeekFrom::Start(src_offset))?;
                            staging_f.seek(SeekFrom::Start(dst_offset))?;
                            let mut rem = len;
                            while rem > 0 {
                                let to_read = (rem as usize).min(copy_buf.len());
                                src_f.read_exact(&mut copy_buf[..to_read])?;
                                staging_f.write_all(&copy_buf[..to_read])?;
                                rem -= to_read as u64;
                            }
                        }
                    }
                }

                // 2. Copy from local chunk store
                if let Some(ref cs) = client_cs {
                    for (dst_offset, hash, _len) in matching_store_chunks {
                        let _ = cs.copy_to_std_file(&hash, &mut staging_f, dst_offset);
                    }
                }

                staging_f.sync_all()?;
                drop(staging_f);

                staging_prepopulated = true;

                // Receive updated TRANSFER_PLAN
                let updated_plan_frame = session.recv_frame().await?;
                if updated_plan_frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
                    anyhow::bail!(
                        "expected TRANSFER_PLAN, got 0x{:02x}",
                        updated_plan_frame.type_byte
                    );
                }
                plan = TransferPlan::decode(updated_plan_frame.payload)?;
            }
        }
    }

    let begin = TransferBegin {
        transfer_id: created.transfer_id,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let is_json = cli_log_json(cli);
    let bytes_to_transfer = plan.bytes_to_transfer;
    let (progress_tx, progress_handle) = if show_progress && !is_json {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(100);
        let tid_str = created.transfer_id.to_string();
        let handle = tokio::spawn(async move {
            let mut transferred = 0u64;
            let mut last_print = std::time::Instant::now();
            let start_time = std::time::Instant::now();
            while let Some(delta) = rx.recv().await {
                transferred = transferred.saturating_add(delta);
                if last_print.elapsed() >= std::time::Duration::from_millis(200)
                    || transferred >= bytes_to_transfer
                {
                    let elapsed_secs = start_time.elapsed().as_secs_f64();
                    let rate = if elapsed_secs > 0.0 {
                        transferred as f64 / elapsed_secs
                    } else {
                        0.0
                    };
                    let pct = if bytes_to_transfer > 0 {
                        (transferred as f64 / bytes_to_transfer as f64) * 100.0
                    } else {
                        100.0
                    };
                    eprint!(
                        "\r[{}] {} / {} ({:.1}%) — {}/s",
                        tid_str,
                        format_bytes(transferred),
                        format_bytes(bytes_to_transfer),
                        pct,
                        format_bytes(rate as u64)
                    );
                    last_print = std::time::Instant::now();
                }
            }
            if transferred > 0 {
                eprintln!();
            }
        });
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };

    let (send_half, recv_half) = session.stream_halves_mut();
    let computed = velcrux_core::client_download_stream_with_staging(
        conn,
        send_half,
        recv_half,
        created.transfer_id,
        local.clone(),
        progress_tx,
        staging_prepopulated,
    )
    .await?;

    if let Some(h) = progress_handle {
        let _ = h.await;
    }

    if let Some(ref cs) = client_cs {
        let params =
            velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
        let _ = cs.ingest_file_sync(local, velcrux_core::chunking::ChunkMode::Fixed, params);
    }

    Ok((created.transfer_id, computed, plan.bytes_to_transfer))
}

async fn delete_remote_file(session: &mut ClientSession, remote_path: &str) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Committed, Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let create = TransferCreate {
        op: TransferOp::Delete,
        src_path: "".into(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::COMMITTED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!(
                "remote delete failed: code={:?} detail={:?}",
                err.code,
                err.detail
            );
        }
        anyhow::bail!(
            "expected COMMITTED for delete, got 0x{:02x}",
            frame.type_byte
        );
    }
    let _committed = Committed::decode(frame.payload)?;
    Ok(())
}

async fn run_download(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    local: &PathBuf,
    url_path: &str,
) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let (tid, computed, total_bytes) =
        download_file_stream(conn, session, url_path, local, true, cli).await?;

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "transfer_complete",
            "op": "download",
            "transfer_id": tid.to_string(),
            "bytes_completed": total_bytes,
            "file_hash": computed.to_string(),
            "local_path": local.display().to_string(),
            "status": "committed"
        });
        println!("{out}");
    } else {
        println!("transfer_id: {tid}");
        println!("download: committed to {local:?}, hash {computed}");
    }
    session.bye().await.ok();
    Ok(())
}

async fn run_remote_upload_sync(
    cli: &Cli,
    source: &str,
    destination: &str,
    dry_run: bool,
    delete_after: bool,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let src_dir = PathBuf::from(source);
    if !src_dir.exists() {
        anyhow::bail!("source path does not exist: {}", src_dir.display());
    }
    if !src_dir.is_dir() {
        anyhow::bail!("source must be a directory: {}", src_dir.display());
    }

    let (addr, path) = parse_url_with_path(destination)?;
    let sni = get_sni(cli, destination);
    let transport = build_transport(cli)?;
    let conn = transport.connect(addr, &sni).await?;
    let mut session = open_client_session(&conn, cli).await?;
    let store = open_client_state_store(cli);

    let src_files = velcrux_core::sync::scan_dir_entries(&src_dir)?;
    let vpath = path.trim_start_matches('/').to_string();

    let create = TransferCreate {
        op: TransferOp::SyncUpload,
        src_path: "".into(),
        dst_path: vpath.clone(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }

    let dst_files =
        velcrux_core::sync::recv_directory_manifest(session.recv_mut().as_mut()).await?;
    let plan = velcrux_core::sync::plan_directory_diff(&src_files, &dst_files);

    let is_json = cli_log_json(cli);

    if dry_run {
        if is_json {
            let actions: Vec<_> = plan
                .actions
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "action": format!("{:?}", a.action).to_lowercase(),
                        "path": a.rel_path,
                        "size": a.src_size,
                        "reused": a.bytes_reusable,
                    })
                })
                .collect();
            let out = serde_json::json!({
                "v": 1,
                "event": "sync_summary",
                "dry_run": true,
                "source": source,
                "destination": destination,
                "files_unchanged": plan.summary.files_unchanged,
                "files_modified": plan.summary.files_modified,
                "files_added": plan.summary.files_added,
                "files_deleted": plan.summary.files_deleted,
                "data_present": plan.summary.data_present,
                "data_to_transfer": plan.summary.data_to_transfer,
                "files_transferred": 0,
                "files_committed": 0,
                "files_deleted_count": 0,
                "actions": actions,
            });
            println!("{out}");
        } else {
            println!("{}", plan.summary.format_display());
        }
        session.bye().await.ok();
        return Ok(());
    }

    if !is_json {
        println!("{}", plan.summary.format_display());
    }

    let mut files_transferred = 0usize;
    let mut files_committed = 0usize;
    let mut files_deleted = 0usize;
    let mut wire_bytes = 0u64;

    for item in &plan.actions {
        match item.action {
            velcrux_core::sync::FileActionType::Add
            | velcrux_core::sync::FileActionType::Modify => {
                let local_file = src_dir.join(&item.rel_path);
                let remote_file = if vpath.is_empty() {
                    item.rel_path.clone()
                } else {
                    format!("{}/{}", vpath.trim_end_matches('/'), item.rel_path)
                };
                let (_tid, _hash, size) = upload_file_stream(
                    &conn,
                    &mut session,
                    &store,
                    &local_file,
                    &remote_file,
                    false,
                    cli,
                )
                .await?;
                files_transferred += 1;
                files_committed += 1;
                wire_bytes += size;
            }
            velcrux_core::sync::FileActionType::Delete => {
                if delete_after {
                    let remote_file = if vpath.is_empty() {
                        item.rel_path.clone()
                    } else {
                        format!("{}/{}", vpath.trim_end_matches('/'), item.rel_path)
                    };
                    delete_remote_file(&mut session, &remote_file).await?;
                    files_deleted += 1;
                }
            }
            velcrux_core::sync::FileActionType::Unchanged => {}
        }
    }

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "sync_summary",
            "dry_run": false,
            "source": source,
            "destination": destination,
            "files_unchanged": plan.summary.files_unchanged,
            "files_modified": plan.summary.files_modified,
            "files_added": plan.summary.files_added,
            "files_deleted": plan.summary.files_deleted,
            "data_present": plan.summary.data_present,
            "data_to_transfer": plan.summary.data_to_transfer,
            "files_transferred": files_transferred,
            "files_committed": files_committed,
            "files_deleted_count": files_deleted,
            "wire_bytes_transferred": wire_bytes,
        });
        println!("{out}");
    } else {
        println!();
        println!(
            "Transferred: {} files (committed: {}, deleted: {})",
            files_transferred, files_committed, files_deleted
        );
        println!("Wire data: {}", format_bytes(wire_bytes));
    }

    session.bye().await.ok();
    Ok(())
}

async fn run_remote_download_sync(
    cli: &Cli,
    source: &str,
    destination: &str,
    dry_run: bool,
    delete_after: bool,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let dst_dir = PathBuf::from(destination);
    if !dst_dir.exists() {
        std::fs::create_dir_all(&dst_dir)?;
    }

    let (addr, path) = parse_url_with_path(source)?;
    let sni = get_sni(cli, source);
    let transport = build_transport(cli)?;
    let conn = transport.connect(addr, &sni).await?;
    let mut session = open_client_session(&conn, cli).await?;

    let dst_files = velcrux_core::sync::scan_dir_entries(&dst_dir)?;
    let vpath = path.trim_start_matches('/').to_string();

    let create = TransferCreate {
        op: TransferOp::SyncDownload,
        src_path: vpath.clone(),
        dst_path: "".into(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }

    let src_files =
        velcrux_core::sync::recv_directory_manifest(session.recv_mut().as_mut()).await?;
    let plan = velcrux_core::sync::plan_directory_diff(&src_files, &dst_files);

    let is_json = cli_log_json(cli);

    if dry_run {
        if is_json {
            let actions: Vec<_> = plan
                .actions
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "action": format!("{:?}", a.action).to_lowercase(),
                        "path": a.rel_path,
                        "size": a.src_size,
                        "reused": a.bytes_reusable,
                    })
                })
                .collect();
            let out = serde_json::json!({
                "v": 1,
                "event": "sync_summary",
                "dry_run": true,
                "source": source,
                "destination": destination,
                "files_unchanged": plan.summary.files_unchanged,
                "files_modified": plan.summary.files_modified,
                "files_added": plan.summary.files_added,
                "files_deleted": plan.summary.files_deleted,
                "data_present": plan.summary.data_present,
                "data_to_transfer": plan.summary.data_to_transfer,
                "files_transferred": 0,
                "files_committed": 0,
                "files_deleted_count": 0,
                "actions": actions,
            });
            println!("{out}");
        } else {
            println!("{}", plan.summary.format_display());
        }
        session.bye().await.ok();
        return Ok(());
    }

    if !is_json {
        println!("{}", plan.summary.format_display());
    }

    let mut files_transferred = 0usize;
    let mut files_committed = 0usize;
    let mut files_deleted = 0usize;
    let mut wire_bytes = 0u64;

    for item in &plan.actions {
        match item.action {
            velcrux_core::sync::FileActionType::Add
            | velcrux_core::sync::FileActionType::Modify => {
                let remote_file = if vpath.is_empty() {
                    item.rel_path.clone()
                } else {
                    format!("{}/{}", vpath.trim_end_matches('/'), item.rel_path)
                };
                let local_file = dst_dir.join(&item.rel_path);
                if let Some(parent) = local_file.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let (_tid, _hash, size) = download_file_stream(
                    &conn,
                    &mut session,
                    &remote_file,
                    &local_file,
                    false,
                    cli,
                )
                .await?;
                files_transferred += 1;
                files_committed += 1;
                wire_bytes += size;
            }
            velcrux_core::sync::FileActionType::Delete => {
                if delete_after {
                    let local_file = dst_dir.join(&item.rel_path);
                    if local_file.exists() {
                        std::fs::remove_file(&local_file)?;
                        files_deleted += 1;
                    }
                }
            }
            velcrux_core::sync::FileActionType::Unchanged => {}
        }
    }

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "sync_summary",
            "dry_run": false,
            "source": source,
            "destination": destination,
            "files_unchanged": plan.summary.files_unchanged,
            "files_modified": plan.summary.files_modified,
            "files_added": plan.summary.files_added,
            "files_deleted": plan.summary.files_deleted,
            "data_present": plan.summary.data_present,
            "data_to_transfer": plan.summary.data_to_transfer,
            "files_transferred": files_transferred,
            "files_committed": files_committed,
            "files_deleted_count": files_deleted,
            "wire_bytes_transferred": wire_bytes,
        });
        println!("{out}");
    } else {
        println!();
        println!(
            "Transferred: {} files (committed: {}, deleted: {})",
            files_transferred, files_committed, files_deleted
        );
        println!("Wire data: {}", format_bytes(wire_bytes));
    }

    session.bye().await.ok();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_sync(
    cli: &Cli,
    source: &str,
    destination: &str,
    dry_run: bool,
    delete_after: bool,
    delete: bool,
    cdc: bool,
    dedup: bool,
    chunk_store_path: &Option<PathBuf>,
) -> anyhow::Result<()> {
    let src_is_remote = source.starts_with("velcrux://");
    let dst_is_remote = destination.starts_with("velcrux://");

    if src_is_remote && dst_is_remote {
        anyhow::bail!("cross-server sync between two remote URLs is not supported");
    }

    if dst_is_remote {
        return run_remote_upload_sync(cli, source, destination, dry_run, delete_after || delete)
            .await;
    }

    if src_is_remote {
        return run_remote_download_sync(cli, source, destination, dry_run, delete_after || delete)
            .await;
    }

    use velcrux_core::chunking::{ChunkMode, ChunkParams};
    use velcrux_core::storage::LocalChunkStore;
    use velcrux_core::sync::{execute_directory_sync, DeleteMode, DirectorySyncOptions};

    let src_path = PathBuf::from(source);
    let dst_path = PathBuf::from(destination);

    if !src_path.exists() {
        anyhow::bail!("source path does not exist: {}", src_path.display());
    }

    let delete_mode = if delete_after || delete {
        DeleteMode::DeleteAfter
    } else {
        DeleteMode::None
    };

    let mode = if cdc {
        ChunkMode::Cdc
    } else {
        ChunkMode::Fixed
    };

    let params = if cdc {
        ChunkParams::new(256 * 1024, 1024 * 1024, 4 * 1024 * 1024)
            .ok_or_else(|| anyhow::anyhow!("invalid CDC chunk params"))?
    } else {
        ChunkParams::new(1024 * 1024, 1024 * 1024, 1024 * 1024)
            .ok_or_else(|| anyhow::anyhow!("invalid fixed chunk params"))?
    };

    let options = DirectorySyncOptions {
        mode,
        params,
        delete_mode,
        dry_run,
        read_buffer_size: 2 * 1024 * 1024,
    };

    let store = if dedup {
        let store_dir = chunk_store_path
            .clone()
            .unwrap_or_else(|| dst_path.join(".velcrux-chunks"));
        Some(LocalChunkStore::new(&store_dir).await?)
    } else {
        None
    };

    let result = execute_directory_sync(&src_path, &dst_path, &options, None, store.as_ref())
        .map_err(|e| anyhow::anyhow!("sync failed: {e}"))?;

    let is_json = cli_log_json(cli);
    if is_json {
        let actions: Vec<_> = result
            .plan
            .actions
            .iter()
            .map(|a| {
                serde_json::json!({
                    "action": format!("{:?}", a.action).to_lowercase(),
                    "path": a.rel_path,
                    "size": a.src_size,
                    "reused": a.bytes_reusable,
                })
            })
            .collect();
        let out = serde_json::json!({
            "v": 1,
            "event": "sync_summary",
            "dry_run": dry_run,
            "source": source,
            "destination": destination,
            "files_unchanged": result.plan.summary.files_unchanged,
            "files_modified": result.plan.summary.files_modified,
            "files_added": result.plan.summary.files_added,
            "files_deleted": result.plan.summary.files_deleted,
            "data_present": result.plan.summary.data_present,
            "data_to_transfer": result.plan.summary.data_to_transfer,
            "files_transferred": result.files_transferred,
            "files_committed": result.files_committed,
            "files_deleted_count": result.files_deleted,
            "actions": actions,
        });
        println!("{out}");
    } else {
        println!("{}", result.plan.summary.format_display());

        if !dry_run {
            println!();
            println!(
                "Transferred: {} files (committed: {}, deleted: {})",
                result.files_transferred, result.files_committed, result.files_deleted
            );
            println!(
                "Wire data: {} | Local reused: {} | Store reused: {}",
                format_bytes(result.wire_bytes_transferred),
                format_bytes(result.local_bytes_reused),
                format_bytes(result.store_bytes_reused)
            );
        }
    }

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.2} TB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}
