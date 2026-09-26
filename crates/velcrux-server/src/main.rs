//! `velcruxd` daemon CLI.
//!
//! M1 subcommands:
//!   - `run --config path.toml`    — accept connections, serve the HELLO/PING service.
//!   - `gen-dev-ca --out path`     — issue a 30-day Ed25519 dev CA.
//!   - `gen-dev-cert --host NAME`  — issue a 24-hour server cert signed by the dev CA.
//!   - `gen-dev-cert --client NAME`— issue a 24-hour client cert signed by the dev CA.

#![forbid(unsafe_code)]

pub mod config;
mod dev_pki;
pub mod limits;
pub mod metrics;
mod server;
pub mod sessions;

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Log format: "text" (default) or "json".
    #[arg(long, default_value = "text", global = true)]
    log_format: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the server.
    Run {
        /// Path to a TOML config file.
        #[arg(long, short)]
        config: PathBuf,
    },
    /// Issue a development Certificate Authority.
    GenDevCa {
        /// Output directory; the CA's cert and key are written here.
        #[arg(long, short)]
        out: PathBuf,
        /// Validity in days. Default: 30 (`DEVELOPMENT.md` §3).
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
    /// Issue a development certificate signed by the dev CA.
    GenDevCert {
        /// Output directory.
        #[arg(long, short)]
        out: PathBuf,
        /// Directory holding the dev CA (must contain `ca.crt` and `ca.key`).
        #[arg(long)]
        ca: PathBuf,
        /// Issue a server cert for this hostname (SAN DNS). Repeatable.
        #[arg(long, value_delimiter = ',')]
        host: Vec<String>,
        /// Issue a client cert with this identity (SAN URI `velcrux://identity/<name>`).
        #[arg(long, conflicts_with = "host")]
        client: Option<String>,
        /// Validity in hours. Default: 24 (`DEVELOPMENT.md` §3).
        #[arg(long, default_value_t = 24)]
        hours: u32,
    },
    /// Generate shell completion script (bash, zsh, fish, powershell, elvish).
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
    /// Garbage-collect unreferenced chunks or orphaned staging files (docs/OPERATIONS.md §6).
    Gc {
        /// Path to a TOML config file.
        #[arg(long, short)]
        config: PathBuf,

        /// Clean up unreferenced chunks in the content-addressed chunk store.
        #[arg(long)]
        chunks: bool,

        /// Clean up orphaned staging directories and partial files.
        #[arg(long)]
        staging: bool,

        /// Report reclaimable disk space without making any filesystem modifications.
        #[arg(long)]
        dry_run: bool,
    },
    /// List active client sessions (docs/OPERATIONS.md §6).
    Sessions {
        /// Path to a TOML config file.
        #[arg(long, short)]
        config: PathBuf,

        /// Output format: "table" (default) or "json".
        #[arg(long, default_value = "table")]
        format: String,
    },
    /// Terminate active client session(s) by identity or connection ID (docs/OPERATIONS.md §6).
    KillSession {
        /// Path to a TOML config file.
        #[arg(long, short)]
        config: PathBuf,

        /// Authenticated peer identity name to terminate.
        #[arg(long)]
        identity: Option<String>,

        /// Connection ID to terminate.
        #[arg(long)]
        conn_id: Option<u64>,
    },
}

fn init_tracing(format: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,velcrux_core=debug,velcrux_server=debug"));
    if format == "json" {
        let _ = fmt().with_env_filter(filter).json().try_init();
    } else {
        let _ = fmt().with_env_filter(filter).try_init();
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_format);

    match cli.cmd {
        Cmd::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "velcruxd", &mut std::io::stdout());
            return Ok(());
        }
        Cmd::Run { config } => {
            info!(config = %config.display(), "starting velcruxd");
            server::run(&config)
                .await
                .with_context(|| format!("server crashed (config: {})", config.display()))?;
        }
        Cmd::GenDevCa { out, days } => {
            std::fs::create_dir_all(&out)
                .with_context(|| format!("create_dir_all {}", out.display()))?;
            dev_pki::issue_dev_ca(&out, days)?;
            println!("dev CA written to {}", out.display());
        }
        Cmd::GenDevCert {
            out,
            ca,
            host,
            client,
            hours,
        } => {
            std::fs::create_dir_all(&out)
                .with_context(|| format!("create_dir_all {}", out.display()))?;
            if let Some(name) = client {
                dev_pki::issue_client_cert(&ca, &out, &name, hours)?;
                println!("client cert for {name} written to {}", out.display());
            } else if !host.is_empty() {
                dev_pki::issue_server_cert(&ca, &out, &host, hours)?;
                println!("server cert for {:?} written to {}", host, out.display());
            } else {
                anyhow::bail!("--host or --client is required");
            }
        }
        Cmd::Gc {
            config,
            mut chunks,
            mut staging,
            dry_run,
        } => {
            use std::path::Path;

            if !chunks && !staging {
                chunks = true;
                staging = true;
            }

            let cfg = config::ServerConfig::load(&config)
                .with_context(|| format!("load config {}", config.display()))?;

            if staging {
                let staging_path = PathBuf::from(&cfg.storage.staging);
                let state_db_path = cfg
                    .storage
                    .state_db
                    .as_ref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        staging_path
                            .parent()
                            .unwrap_or(Path::new("."))
                            .join("state.db")
                    });

                if state_db_path.exists() && staging_path.exists() {
                    let state_store = velcrux_core::SqliteStateStore::new(&state_db_path)
                        .with_context(|| format!("open state store {}", state_db_path.display()))?;
                    let report = velcrux_core::gc_staging(&staging_path, &state_store, dry_run)
                        .with_context(|| "garbage collect staging")?;

                    if dry_run {
                        println!(
                            "[GC:staging:dry-run] scanned={}, orphans_found={}, reclaimable_bytes={}",
                            report.entries_scanned, report.orphans_found, report.bytes_reclaimed
                        );
                    } else {
                        println!(
                            "[GC:staging] scanned={}, orphans_deleted={}, bytes_reclaimed={}",
                            report.entries_scanned, report.orphans_deleted, report.bytes_reclaimed
                        );
                    }
                } else {
                    println!("[GC:staging] staging directory or state DB not found; skipped.");
                }
            }

            if chunks {
                let storage_root = PathBuf::from(&cfg.storage.root);
                let chunk_store_path = cfg
                    .storage
                    .chunk_store
                    .as_ref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        storage_root
                            .parent()
                            .unwrap_or(Path::new("."))
                            .join("chunks")
                    });

                if chunk_store_path.exists() {
                    let chunk_store = velcrux_core::LocalChunkStore::new(&chunk_store_path)
                        .await
                        .with_context(|| {
                            format!("open chunk store {}", chunk_store_path.display())
                        })?;
                    let report =
                        velcrux_core::gc_chunk_store(&chunk_store, &[&storage_root], dry_run)
                            .with_context(|| "garbage collect chunk store")?;

                    if dry_run {
                        println!(
                            "[GC:chunks:dry-run] scanned={}, unreferenced_found={}, reclaimable_bytes={}",
                            report.chunks_scanned,
                            report.unreferenced_found,
                            report.bytes_reclaimed
                        );
                    } else {
                        println!(
                            "[GC:chunks] scanned={}, unreferenced_deleted={}, bytes_reclaimed={}",
                            report.chunks_scanned,
                            report.unreferenced_deleted,
                            report.bytes_reclaimed
                        );
                    }
                } else {
                    println!("[GC:chunks] chunk store path not found; skipped.");
                }
            }
        }
        Cmd::Sessions { config, format } => {
            let cfg = config::ServerConfig::load(&config)
                .with_context(|| format!("load config {}", config.display()))?;
            let listen = cfg
                .telemetry
                .metrics_listen
                .unwrap_or_else(|| "127.0.0.1:9090".to_string());
            let addr = resolve_admin_addr(&listen);

            let body = admin_request(&addr, "GET", "/admin/sessions").await?;
            if format.eq_ignore_ascii_case("json") {
                println!("{body}");
            } else {
                let sessions: Vec<sessions::SessionInfo> = serde_json::from_str(&body)
                    .with_context(|| "parse sessions response from admin endpoint")?;
                if sessions.is_empty() {
                    println!("No active sessions.");
                } else {
                    println!(
                        "{:<8} {:<24} {:<24} {:<10}",
                        "CONN ID", "IDENTITY", "REMOTE ADDRESS", "UPTIME"
                    );
                    println!("{:-<8} {:-<24} {:-<24} {:-<10}", "", "", "", "");
                    for s in sessions {
                        let ident = s.identity.as_deref().unwrap_or("<unauthenticated>");
                        let uptime = format!("{}s", s.uptime_secs);
                        println!(
                            "{:<8} {:<24} {:<24} {:<10}",
                            s.conn_id, ident, s.remote_addr, uptime
                        );
                    }
                }
            }
        }
        Cmd::KillSession {
            config,
            identity,
            conn_id,
        } => {
            if identity.is_none() && conn_id.is_none() {
                anyhow::bail!("either --identity or --conn-id is required");
            }
            let cfg = config::ServerConfig::load(&config)
                .with_context(|| format!("load config {}", config.display()))?;
            let listen = cfg
                .telemetry
                .metrics_listen
                .unwrap_or_else(|| "127.0.0.1:9090".to_string());
            let addr = resolve_admin_addr(&listen);

            let path = if let Some(id) = identity {
                format!("/admin/kill-session?identity={}", percent_encode(&id))
            } else if let Some(cid) = conn_id {
                format!("/admin/kill-session?conn_id={cid}")
            } else {
                unreachable!()
            };

            let body = admin_request(&addr, "POST", &path).await?;
            #[derive(serde::Deserialize)]
            struct KillResp {
                killed: usize,
            }
            let resp: KillResp = serde_json::from_str(&body)
                .with_context(|| "parse kill-session response from admin endpoint")?;
            if resp.killed > 0 {
                println!("Successfully terminated {} active session(s).", resp.killed);
            } else {
                println!("No matching active sessions found.");
            }
        }
    }
    Ok(())
}

fn resolve_admin_addr(listen: &str) -> String {
    if let Some(port) = listen.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{port}")
    } else if let Some(port) = listen.strip_prefix("[::]:") {
        format!("[::1]:{port}")
    } else {
        listen.to_string()
    }
}

async fn admin_request(addr: &str, method: &str, path: &str) -> anyhow::Result<String> {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("failed to connect to admin endpoint at http://{addr}"))?;

        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: velcruxd-cli\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .with_context(|| "failed to send request to admin endpoint")?;

        let mut resp = String::new();
        stream
            .read_to_string(&mut resp)
            .await
            .with_context(|| "failed to read response from admin endpoint")?;

        if let Some((headers, body)) = resp.split_once("\r\n\r\n") {
            let status_line = headers.lines().next().unwrap_or("");
            if !status_line.contains("200") {
                anyhow::bail!("admin endpoint error: {status_line}");
            }
            Ok(body.to_string())
        } else {
            Ok(resp)
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timeout communicating with admin endpoint at http://{addr}"))?
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{:02X}", b);
        }
    }
    out
}
