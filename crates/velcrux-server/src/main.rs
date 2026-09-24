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
pub mod metrics;
mod server;

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
    }
    Ok(())
}
