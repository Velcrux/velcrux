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
use velcrux_core::transport::{Connection, SharedTransport};

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
    },
    /// Cancel an in-progress transfer. M3.
    Cancel {
        /// Transfer id (26-character ULID).
        transfer_id: String,
    },
    /// Show state of a single transfer. M3.
    Stat {
        /// Transfer id (26-character ULID).
        transfer_id: String,
    },
    /// List transfers by URL prefix. M3.
    List {
        /// URL prefix, e.g. `velcrux://host:7443/data/`.
        url_prefix: String,
    },
}

fn init_tracing(format: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,velcrux_core=debug"));
    if format == "json" {
        let _ = fmt().with_env_filter(filter).json().try_init();
    } else {
        let _ = fmt().with_env_filter(filter).try_init();
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
    let addrs = (host, port)
        .to_socket_addrs()
        .context("invalid host:port")?;
    addrs
        .into_iter()
        .next()
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
    let addr = (host, port)
        .to_socket_addrs()
        .context("invalid host:port")?
        .into_iter()
        .next()
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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_format);

    match &cli.cmd {
        Cmd::Ping { url } => {
            let addr = parse_url(url)?;
            let sni = cli.sni.clone().unwrap_or_else(|| {
                url.split("://")
                    .nth(1)
                    .unwrap_or("localhost")
                    .split(':')
                    .next()
                    .unwrap_or("localhost")
                    .to_string()
            });
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
            let sni = cli.sni.clone().unwrap_or_else(|| {
                url.split("://")
                    .nth(1)
                    .unwrap_or("localhost")
                    .split(':')
                    .next()
                    .unwrap_or("localhost")
                    .to_string()
            });
            let transport = build_transport(&cli)?;
            info!(%addr, %sni, ?path, "connecting");
            let conn = transport.connect(addr, &sni).await?;
            let (send, recv) = conn.open_bi().await?;
            let mut session = ClientSession::from_handshake_parts(send, recv).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            run_upload(&conn, &mut session, local, &path).await?;
        }
        Cmd::Download { url, local } => {
            let (addr, path) = parse_url_with_path(url)?;
            let sni = cli.sni.clone().unwrap_or_else(|| {
                url.split("://")
                    .nth(1)
                    .unwrap_or("localhost")
                    .split(':')
                    .next()
                    .unwrap_or("localhost")
                    .to_string()
            });
            let transport = build_transport(&cli)?;
            info!(%addr, %sni, ?path, "connecting");
            let conn = transport.connect(addr, &sni).await?;
            let (send, recv) = conn.open_bi().await?;
            let mut session = ClientSession::from_handshake_parts(send, recv).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            run_download(&conn, &mut session, local, &path).await?;
        }
        Cmd::Resume { transfer_id } => {
            anyhow::bail!(
                "`velcrux resume {}` is a stub in this revision; \
                 use the M3 integration test or call TRANSFER_CREATE \
                 with the same idempotency key (see tests/m3_resume.rs).",
                transfer_id
            );
        }
        Cmd::Cancel { transfer_id } => {
            let (addr, _) = parse_url_with_path("velcrux://localhost:7443/")?;
            let sni = "localhost".to_string();
            let transport = build_transport(&cli)?;
            let conn = transport.connect(addr, &sni).await?;
            let (send, recv) = conn.open_bi().await?;
            let mut session = ClientSession::from_handshake_parts(send, recv).await?;
            run_cancel(&mut session, &transfer_id).await?;
        }
        Cmd::Stat { transfer_id } => {
            let (addr, _) = parse_url_with_path("velcrux://localhost:7443/")?;
            let sni = "localhost".to_string();
            let transport = build_transport(&cli)?;
            let conn = transport.connect(addr, &sni).await?;
            let (send, recv) = conn.open_bi().await?;
            let mut session = ClientSession::from_handshake_parts(send, recv).await?;
            run_stat(&mut session, &transfer_id).await?;
        }
        Cmd::List { url_prefix } => {
            let (addr, _) = parse_url_with_path(&url_prefix)?;
            let sni = "localhost".to_string();
            let transport = build_transport(&cli)?;
            let conn = transport.connect(addr, &sni).await?;
            let (send, recv) = conn.open_bi().await?;
            let mut session = ClientSession::from_handshake_parts(send, recv).await?;
            run_list(&mut session, &url_prefix).await?;
        }
    }
    Ok(())
}

async fn run_upload(
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    local: &PathBuf,
    url_path: &str,
) -> anyhow::Result<()> {
    use std::io::Read;
    use velcrux_core::protocol::message::{
        Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    };
    use velcrux_core::session::encode_message;

    let file_size = std::fs::metadata(local)
        .with_context(|| format!("stat {local:?}"))?
        .len();
    let expected_hash = {
        let mut f = std::fs::File::open(local).with_context(|| format!("open {local:?}"))?;
        let mut h = velcrux_core::HashHasher::new();
        let mut buf = vec![0u8; 2 * 1024 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .with_context(|| format!("read {local:?}"))?;
            if n == 0 {
                break;
            }
            h.feed(&buf[..n]);
        }
        h.finalize()
    };

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: local.display().to_string(),
        dst_path: url_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size,
        file_hash: expected_hash,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }
    let created = TransferCreated::decode(&frame.payload)?;
    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
        anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", frame.type_byte);
    }
    let _plan = TransferPlan::decode(&frame.payload)?;

    let begin = TransferBegin {
        transfer_id: created.transfer_id,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let cfg = velcrux_core::PipelineConfig::default();
    let computed = velcrux_core::client_upload(
        conn,
        session.send_mut_owned(),
        session.recv_mut_owned(),
        created.transfer_id,
        local.clone(),
        file_size,
        expected_hash,
        cfg,
    )
    .await?;
    eprintln!(
        "upload: committed {} bytes; server hash matches: {}",
        file_size,
        computed == expected_hash
    );
    Ok(())
}

async fn run_stat(session: &mut ClientSession, transfer_id_str: &str) -> anyhow::Result<()> {
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
    let r = StatResult::decode(&frame.payload)?;
    if !r.found {
        anyhow::bail!("transfer not found: {}", transfer_id_str);
    }
    if cli_log_json() {
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

async fn run_list(session: &mut ClientSession, url_prefix: &str) -> anyhow::Result<()> {
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
    let r = ListResult::decode(&frame.payload)?;
    if cli_log_json() {
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

async fn run_cancel(session: &mut ClientSession, transfer_id_str: &str) -> anyhow::Result<()> {
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
    println!("cancel requested: {transfer_id_str}");
    Ok(())
}

fn cli_log_json() -> bool {
    std::env::var("VELCRUX_OUTPUT_JSON").is_ok()
}

async fn run_download(
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    local: &PathBuf,
    url_path: &str,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{
        Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    };
    use velcrux_core::session::encode_message;

    let create = TransferCreate {
        op: TransferOp::Download,
        src_path: "".into(),
        dst_path: url_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }
    let created = TransferCreated::decode(&frame.payload)?;
    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
        anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", frame.type_byte);
    }
    let _plan = TransferPlan::decode(&frame.payload)?;

    let begin = TransferBegin {
        transfer_id: created.transfer_id,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let computed = velcrux_core::client_download(
        conn,
        session.send_mut_owned(),
        session.recv_mut_owned(),
        created.transfer_id,
        local.clone(),
    )
    .await?;
    eprintln!("download: committed to {local:?}, hash {computed}");
    Ok(())
}
