//! Production configuration engine (`docs/OPERATIONS.md` §4).
//!
//! Supports TOML configuration, environment variable overrides with prefix
//! `VELCRUX_`, and strict startup validation.

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub network: NetworkCfg,
    #[serde(default)]
    pub quic: QuicCfg,
    #[serde(default)]
    pub transfer: TransferCfg,
    #[serde(default)]
    pub hash: HashCfg,
    pub security: SecurityCfg,
    pub storage: StorageCfg,
    #[serde(default)]
    pub telemetry: TelemetryCfg,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkCfg {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub max_bandwidth: Option<String>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub max_connections_per_ip: Option<u32>,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: String,
    #[serde(default = "default_keepalive")]
    pub keepalive: String,
}

impl Default for NetworkCfg {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            max_bandwidth: None,
            max_connections: None,
            max_connections_per_ip: None,
            idle_timeout: default_idle_timeout(),
            keepalive: default_keepalive(),
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:7443".into()
}
fn default_idle_timeout() -> String {
    "60s".into()
}
fn default_keepalive() -> String {
    "15s".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuicCfg {
    #[serde(default = "default_window")]
    pub receive_window: String,
    #[serde(default = "default_window")]
    pub stream_receive_window: String,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    #[serde(default = "default_initial_rtt")]
    pub initial_rtt: String,
    #[serde(default = "default_true")]
    pub gso: bool,
}

impl Default for QuicCfg {
    fn default() -> Self {
        Self {
            receive_window: default_window(),
            stream_receive_window: default_window(),
            max_concurrent_streams: default_max_concurrent_streams(),
            initial_rtt: default_initial_rtt(),
            gso: true,
        }
    }
}

fn default_window() -> String {
    "384MiB".into()
}
fn default_max_concurrent_streams() -> u32 {
    32
}
fn default_initial_rtt() -> String {
    "150ms".into()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TransferCfg {
    #[serde(default)]
    pub chunking: Option<String>,
    #[serde(default)]
    pub chunk_min: Option<String>,
    #[serde(default)]
    pub chunk_target: Option<String>,
    #[serde(default)]
    pub chunk_max: Option<String>,
    #[serde(default)]
    pub parallelism: Option<usize>,
    #[serde(default)]
    pub resume: Option<bool>,
    #[serde(default)]
    pub compression: Option<String>,
    #[serde(default)]
    pub checkpoint_bytes: Option<String>,
    #[serde(default)]
    pub checkpoint_secs: Option<u64>,
    #[serde(default)]
    pub read_buffer: Option<String>,
    #[serde(default)]
    pub max_file_size: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HashCfg {
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub workers: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityCfg {
    pub certificate: String,
    pub private_key: String,
    pub client_ca: String,
    #[serde(default)]
    pub crl: Option<String>,
    #[serde(default)]
    pub max_auth_attempts: Option<u32>,
    #[serde(default)]
    pub grants: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageCfg {
    pub root: String,
    pub staging: String,
    #[serde(default)]
    pub state_db: Option<String>,
    #[serde(default)]
    pub chunk_store: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TelemetryCfg {
    #[serde(default)]
    pub metrics_listen: Option<String>,
    #[serde(default)]
    pub log_format: Option<String>,
    #[serde(default)]
    pub log_level: Option<String>,
}

impl ServerConfig {
    /// Load server configuration from TOML file, then apply environment variable overrides.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("parse TOML from {}", path.display()))?;
        cfg.apply_env_overrides();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Apply environment variable overrides (prefixed with `VELCRUX_`).
    pub fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("VELCRUX_NETWORK_LISTEN") {
            self.network.listen = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_NETWORK_MAX_BANDWIDTH") {
            self.network.max_bandwidth = Some(val);
        }
        if let Ok(val) = std::env::var("VELCRUX_NETWORK_MAX_CONNECTIONS") {
            if let Ok(n) = val.parse() {
                self.network.max_connections = Some(n);
            }
        }
        if let Ok(val) = std::env::var("VELCRUX_NETWORK_IDLE_TIMEOUT") {
            self.network.idle_timeout = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_NETWORK_KEEPALIVE") {
            self.network.keepalive = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_QUIC_RECEIVE_WINDOW") {
            self.quic.receive_window = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_QUIC_STREAM_RECEIVE_WINDOW") {
            self.quic.stream_receive_window = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_SECURITY_CERTIFICATE") {
            self.security.certificate = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_SECURITY_PRIVATE_KEY") {
            self.security.private_key = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_SECURITY_CLIENT_CA") {
            self.security.client_ca = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_SECURITY_CRL") {
            self.security.crl = Some(val);
        }
        if let Ok(val) = std::env::var("VELCRUX_SECURITY_GRANTS") {
            self.security.grants = Some(val);
        }
        if let Ok(val) = std::env::var("VELCRUX_STORAGE_ROOT") {
            self.storage.root = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_STORAGE_STAGING") {
            self.storage.staging = val;
        }
        if let Ok(val) = std::env::var("VELCRUX_STORAGE_STATE_DB") {
            self.storage.state_db = Some(val);
        }
        if let Ok(val) = std::env::var("VELCRUX_STORAGE_CHUNK_STORE") {
            self.storage.chunk_store = Some(val);
        }
        if let Ok(val) = std::env::var("VELCRUX_TELEMETRY_METRICS_LISTEN") {
            self.telemetry.metrics_listen = Some(val);
        }
        if let Ok(val) = std::env::var("VELCRUX_TELEMETRY_LOG_FORMAT") {
            self.telemetry.log_format = Some(val);
        }
        if let Ok(val) = std::env::var("VELCRUX_TELEMETRY_LOG_LEVEL") {
            self.telemetry.log_level = Some(val);
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate listen address
        let _: std::net::SocketAddr = self.network.listen.parse()
            .with_context(|| format!("invalid network.listen address: {}", self.network.listen))?;

        // Validate state_db path (must be absolute per ADR-005)
        if let Some(state_db) = &self.storage.state_db {
            let p = PathBuf::from(state_db);
            if !p.is_absolute() {
                anyhow::bail!("storage.state_db path must be absolute (got {}) per ADR-005", state_db);
            }
        }

        // Validate private key permissions if it is a file on disk
        if !self.security.private_key.starts_with("env:") {
            let key_path = Path::new(&self.security.private_key);
            if key_path.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::metadata(key_path)
                        .with_context(|| format!("stat private key {}", key_path.display()))?
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
        }

        Ok(())
    }

    /// Read the private key bytes either from the file path or environment variable.
    pub fn read_private_key_pem(&self) -> Result<Vec<u8>> {
        if let Some(var_name) = self.security.private_key.strip_prefix("env:") {
            let val = std::env::var(var_name)
                .with_context(|| format!("private key env var {var_name} not found"))?;
            Ok(val.into_bytes())
        } else {
            std::fs::read(&self.security.private_key)
                .with_context(|| format!("read key {}", self.security.private_key))
        }
    }
}

/// Parse human-readable byte sizes (e.g. "384MiB", "1GiB", "256KiB", "100").
pub fn parse_size_bytes(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_suffix("TiB") {
        let n: u64 = rest.trim().parse()?;
        return Ok(n * 1024 * 1024 * 1024 * 1024);
    }
    if let Some(rest) = s.strip_suffix("GiB") {
        let n: u64 = rest.trim().parse()?;
        return Ok(n * 1024 * 1024 * 1024);
    }
    if let Some(rest) = s.strip_suffix("MiB") {
        let n: u64 = rest.trim().parse()?;
        return Ok(n * 1024 * 1024);
    }
    if let Some(rest) = s.strip_suffix("KiB") {
        let n: u64 = rest.trim().parse()?;
        return Ok(n * 1024);
    }
    let n: u64 = s.parse()?;
    Ok(n)
}
