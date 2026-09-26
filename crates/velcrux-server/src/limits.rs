//! Bandwidth metering, hierarchical rate limiting, and multi-tenant quota enforcement.
//!
//! Implements `OPERATIONS.md` §4, §7, and `SECURITY.md` §3:
//! - Global server bandwidth cap (`network.max_bandwidth`)
//! - Per-tenant bandwidth limits (`[[limits]] max_bandwidth`)
//! - Per-tenant quota enforcement (`[[limits]] quota_bytes`)
//! - Hierarchical token bucket chaining (global parent + tenant child)
//! - Thread-safe hot reloading on SIGHUP without resetting accumulated usage
//! - Metric tracking for bandwidth throttling, quota exhaustion, and connection ceiling

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use tracing::info;
use velcrux_core::parse_rate_limit;
use velcrux_core::session::{LimitsProvider, ServerStats};
use velcrux_core::transfer::RateLimiter;

use crate::config::LimitsCfg;

/// Thread-safe manager for server bandwidth limits, tenant quotas, and connection limits.
pub struct LimitsManager {
    /// Global server bandwidth limiter.
    global_limiter: Arc<RwLock<Arc<RateLimiter>>>,
    /// Per-tenant rate limiters keyed by tenant identity.
    tenant_limiters: Arc<RwLock<HashMap<String, Arc<RateLimiter>>>>,
    /// Per-tenant quota cap in bytes.
    quotas: Arc<RwLock<HashMap<String, u64>>>,
    /// Accumulated transfer usage per tenant in bytes.
    usage: Arc<RwLock<HashMap<String, u64>>>,
    /// Configured maximum concurrent connections (0 = unlimited).
    max_connections: AtomicU32,
    /// Shared server statistics.
    stats: Arc<ServerStats>,
}

impl LimitsManager {
    /// Creates a new `LimitsManager` from the server configuration.
    pub fn new(
        network_bandwidth: Option<&str>,
        max_connections: Option<u32>,
        limits: &[LimitsCfg],
        stats: Arc<ServerStats>,
    ) -> anyhow::Result<Self> {
        let global_rate = match network_bandwidth {
            Some(s) => parse_rate_limit(s)
                .map_err(|e| anyhow::anyhow!("invalid network.max_bandwidth '{s}': {e}"))?,
            None => 0,
        };

        let global_limiter = Arc::new(
            RateLimiter::new(global_rate)
                .with_hit_counter(Arc::clone(&stats.resource_limit_hits_bandwidth)),
        );

        let mut tenant_map = HashMap::new();
        let mut quota_map = HashMap::new();

        for limit_cfg in limits {
            let ident = limit_cfg.identity.trim().to_string();
            if ident.is_empty() {
                anyhow::bail!("limits identity cannot be empty");
            }

            if let Some(ref bw) = limit_cfg.max_bandwidth {
                let tenant_rate = parse_rate_limit(bw).map_err(|e| {
                    anyhow::anyhow!("invalid max_bandwidth '{bw}' for identity '{ident}': {e}")
                })?;
                let limiter = Arc::new(
                    RateLimiter::new(tenant_rate)
                        .with_parent(Arc::clone(&global_limiter))
                        .with_hit_counter(Arc::clone(&stats.resource_limit_hits_bandwidth)),
                );
                tenant_map.insert(ident.clone(), limiter);
            }

            if let Some(ref q) = limit_cfg.quota_bytes {
                let quota = parse_rate_limit(q).map_err(|e| {
                    anyhow::anyhow!("invalid quota_bytes '{q}' for identity '{ident}': {e}")
                })?;
                quota_map.insert(ident, quota);
            }
        }

        Ok(Self {
            global_limiter: Arc::new(RwLock::new(global_limiter)),
            tenant_limiters: Arc::new(RwLock::new(tenant_map)),
            quotas: Arc::new(RwLock::new(quota_map)),
            usage: Arc::new(RwLock::new(HashMap::new())),
            max_connections: AtomicU32::new(max_connections.unwrap_or(0)),
            stats,
        })
    }

    /// Hot-reloads rate limits and quotas from reloaded configuration (e.g. on SIGHUP).
    /// Preserves existing accumulated tenant usage.
    pub fn reload(
        &self,
        network_bandwidth: Option<&str>,
        limits: &[LimitsCfg],
    ) -> anyhow::Result<()> {
        let global_rate = match network_bandwidth {
            Some(s) => parse_rate_limit(s)
                .map_err(|e| anyhow::anyhow!("invalid network.max_bandwidth '{s}': {e}"))?,
            None => 0,
        };

        let new_global = Arc::new(
            RateLimiter::new(global_rate)
                .with_hit_counter(Arc::clone(&self.stats.resource_limit_hits_bandwidth)),
        );

        let mut new_tenant_map = HashMap::new();
        let mut new_quota_map = HashMap::new();

        for limit_cfg in limits {
            let ident = limit_cfg.identity.trim().to_string();
            if ident.is_empty() {
                continue;
            }

            if let Some(ref bw) = limit_cfg.max_bandwidth {
                let tenant_rate = parse_rate_limit(bw).map_err(|e| {
                    anyhow::anyhow!("invalid max_bandwidth '{bw}' for identity '{ident}': {e}")
                })?;
                let limiter = Arc::new(
                    RateLimiter::new(tenant_rate)
                        .with_parent(Arc::clone(&new_global))
                        .with_hit_counter(Arc::clone(&self.stats.resource_limit_hits_bandwidth)),
                );
                new_tenant_map.insert(ident.clone(), limiter);
            }

            if let Some(ref q) = limit_cfg.quota_bytes {
                let quota = parse_rate_limit(q).map_err(|e| {
                    anyhow::anyhow!("invalid quota_bytes '{q}' for identity '{ident}': {e}")
                })?;
                new_quota_map.insert(ident, quota);
            }
        }

        if let Ok(mut g) = self.global_limiter.write() {
            *g = new_global;
        }
        if let Ok(mut t) = self.tenant_limiters.write() {
            *t = new_tenant_map;
        }
        if let Ok(mut q) = self.quotas.write() {
            *q = new_quota_map;
        }

        info!("reloaded bandwidth limits and tenant quotas on SIGHUP");
        Ok(())
    }

    /// Check if an incoming connection exceeds `network.max_connections`.
    pub fn check_connection_limit(&self, current_active: u64) -> Result<(), String> {
        let max = self.max_connections.load(Ordering::Relaxed);
        if max > 0 && current_active >= max as u64 {
            self.stats
                .resource_limit_hits_connections
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .resource_limit_hits
                .fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "connection ceiling reached ({current_active} >= {max})"
            ));
        }
        Ok(())
    }

    /// Return the current usage for a tenant in bytes.
    pub fn get_usage(&self, identity: &str) -> u64 {
        self.usage
            .read()
            .ok()
            .and_then(|u| u.get(identity).copied())
            .unwrap_or(0)
    }

    /// Return the configured quota for a tenant in bytes (if any).
    pub fn get_quota(&self, identity: &str) -> Option<u64> {
        self.quotas
            .read()
            .ok()
            .and_then(|q| q.get(identity).copied())
    }

    /// Return the global bandwidth limit in bytes/sec (0 = unlimited).
    pub fn global_bandwidth(&self) -> u64 {
        self.global_limiter
            .read()
            .ok()
            .map(|g| g.bytes_per_sec())
            .unwrap_or(0)
    }

    /// Return the tenant bandwidth limit in bytes/sec (if configured).
    pub fn tenant_bandwidth(&self, identity: &str) -> Option<u64> {
        self.tenant_limiters
            .read()
            .ok()
            .and_then(|t| t.get(identity).map(|l| l.bytes_per_sec()))
    }

    /// Check whether a tenant with `identity` has sufficient quota for `additional_bytes`.
    pub fn check_quota(&self, identity: Option<&str>, additional_bytes: u64) -> Result<(), String> {
        <Self as LimitsProvider>::check_quota(self, identity, additional_bytes)
    }

    /// Record committed bytes to a tenant's quota usage.
    pub fn record_transfer(&self, identity: Option<&str>, bytes_committed: u64) {
        <Self as LimitsProvider>::record_transfer(self, identity, bytes_committed);
    }
}

impl LimitsProvider for LimitsManager {
    fn get_rate_limiter(&self, identity: Option<&str>) -> Option<RateLimiter> {
        if let Some(id) = identity {
            if let Ok(guard) = self.tenant_limiters.read() {
                if let Some(lim) = guard.get(id) {
                    return Some((**lim).clone());
                }
            }
        }

        if let Ok(guard) = self.global_limiter.read() {
            if guard.bytes_per_sec() > 0 {
                return Some((**guard).clone());
            }
        }

        None
    }

    fn check_quota(
        &self,
        identity: Option<&str>,
        additional_bytes: u64,
    ) -> std::result::Result<(), String> {
        let Some(ident) = identity else {
            return Ok(());
        };

        let quotas = match self.quotas.read() {
            Ok(g) => g,
            Err(_) => return Ok(()),
        };

        if let Some(&quota) = quotas.get(ident) {
            let usage = match self.usage.read() {
                Ok(g) => g,
                Err(_) => return Ok(()),
            };
            let current = usage.get(ident).copied().unwrap_or(0);
            if current.saturating_add(additional_bytes) > quota {
                self.stats
                    .resource_limit_hits_quota
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .resource_limit_hits
                    .fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "tenant '{ident}' quota exceeded (used {current} + {additional_bytes} > {quota})"
                ));
            }
        }

        Ok(())
    }

    fn record_transfer(&self, identity: Option<&str>, bytes: u64) {
        if let Some(ident) = identity {
            if bytes > 0 {
                if let Ok(mut usage) = self.usage.write() {
                    let entry = usage.entry(ident.to_string()).or_insert(0);
                    *entry = entry.saturating_add(bytes);
                }
            }
        }
    }
}
