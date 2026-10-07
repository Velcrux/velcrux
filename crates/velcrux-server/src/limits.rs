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
    /// Per-tenant soft quota warning threshold in bytes.
    soft_quotas: Arc<RwLock<HashMap<String, u64>>>,
    /// Active in-flight transfer quota reservations per tenant in bytes.
    reservations: Arc<RwLock<HashMap<String, u64>>>,
    /// Accumulated transfer usage per tenant in bytes.
    usage: Arc<RwLock<HashMap<String, u64>>>,
    /// Cumulative disk storage accounting per tenant identity in bytes.
    tenant_storage_bytes: Arc<RwLock<HashMap<String, u64>>>,
    /// Configured maximum concurrent connections (0 = unlimited).
    max_connections: AtomicU32,
    /// Maximum concurrent connections per IP (0 = unlimited).
    max_connections_per_ip: AtomicU32,
    /// Maximum concurrent unauthenticated connections (0 = unlimited).
    max_connections_unauth: AtomicU32,
    /// Active connections per IP address.
    ip_connections: Arc<RwLock<HashMap<std::net::IpAddr, u32>>>,
    /// Number of active unauthenticated connections.
    unauth_connections: Arc<AtomicU32>,
    /// Shared server statistics.
    stats: Arc<ServerStats>,
}

/// RAII guard representing an active, in-flight quota reservation for a tenant.
///
/// Prevents concurrent transfer race conditions by accounting for in-flight transfer bytes.
/// If dropped before being committed (e.g. on transfer error, cancellation, or disconnect),
/// the reservation is automatically released back to the tenant's quota pool.
#[derive(Debug)]
pub struct QuotaReservation {
    identity: Option<String>,
    bytes: u64,
    committed: bool,
    reservations: Arc<RwLock<HashMap<String, u64>>>,
    usage: Arc<RwLock<HashMap<String, u64>>>,
}

impl QuotaReservation {
    /// Commit the reserved bytes into actual tenant usage and release the in-flight reservation.
    pub fn commit(mut self) {
        self.committed = true;
        if let Some(ref ident) = self.identity {
            if let Ok(mut res) = self.reservations.write() {
                if let Some(r) = res.get_mut(ident) {
                    *r = r.saturating_sub(self.bytes);
                    if *r == 0 {
                        res.remove(ident);
                    }
                }
            }
            if let Ok(mut usage) = self.usage.write() {
                let entry = usage.entry(ident.clone()).or_insert(0);
                *entry = entry.saturating_add(self.bytes);
            }
        }
    }

    /// Explicitly release the reservation without committing it to usage.
    pub fn release(mut self) {
        self.committed = true;
        if let Some(ref ident) = self.identity {
            if let Ok(mut res) = self.reservations.write() {
                if let Some(r) = res.get_mut(ident) {
                    *r = r.saturating_sub(self.bytes);
                    if *r == 0 {
                        res.remove(ident);
                    }
                }
            }
        }
    }

    /// Number of bytes held in this reservation.
    #[inline]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(ref ident) = self.identity {
                if let Ok(mut res) = self.reservations.write() {
                    if let Some(r) = res.get_mut(ident) {
                        *r = r.saturating_sub(self.bytes);
                        if *r == 0 {
                            res.remove(ident);
                        }
                    }
                }
            }
        }
    }
}

/// RAII guard tracking active connections per IP and unauthenticated connections.
#[derive(Debug)]
pub struct ConnectionGuard {
    ip: std::net::IpAddr,
    ip_connections: Arc<RwLock<HashMap<std::net::IpAddr, u32>>>,
    unauth_connections: Arc<AtomicU32>,
    is_unauth: Arc<std::sync::atomic::AtomicBool>,
}

impl ConnectionGuard {
    /// Mark this connection as authenticated, decrementing the unauthenticated connection count.
    pub fn mark_authenticated(&self) {
        if self.is_unauth.swap(false, Ordering::SeqCst) {
            self.unauth_connections.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.is_unauth.swap(false, Ordering::SeqCst) {
            self.unauth_connections.fetch_sub(1, Ordering::SeqCst);
        }
        if let Ok(mut map) = self.ip_connections.write() {
            if let Some(count) = map.get_mut(&self.ip) {
                if *count <= 1 {
                    map.remove(&self.ip);
                } else {
                    *count -= 1;
                }
            }
        }
    }
}

impl LimitsManager {
    /// Creates a new `LimitsManager` from the server configuration.
    pub fn new(
        network_bandwidth: Option<&str>,
        max_connections: Option<u32>,
        max_connections_per_ip: Option<u32>,
        max_connections_unauth: Option<u32>,
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
        let mut soft_quota_map = HashMap::new();

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
                let soft = if let Some(ref sq) = limit_cfg.soft_quota_bytes {
                    parse_rate_limit(sq).map_err(|e| {
                        anyhow::anyhow!(
                            "invalid soft_quota_bytes '{sq}' for identity '{ident}': {e}"
                        )
                    })?
                } else {
                    (quota as f64 * 0.9) as u64
                };
                quota_map.insert(ident.clone(), quota);
                soft_quota_map.insert(ident, soft);
            }
        }

        Ok(Self {
            global_limiter: Arc::new(RwLock::new(global_limiter)),
            tenant_limiters: Arc::new(RwLock::new(tenant_map)),
            quotas: Arc::new(RwLock::new(quota_map)),
            soft_quotas: Arc::new(RwLock::new(soft_quota_map)),
            reservations: Arc::new(RwLock::new(HashMap::new())),
            usage: Arc::new(RwLock::new(HashMap::new())),
            tenant_storage_bytes: Arc::new(RwLock::new(HashMap::new())),
            max_connections: AtomicU32::new(max_connections.unwrap_or(0)),
            max_connections_per_ip: AtomicU32::new(max_connections_per_ip.unwrap_or(0)),
            max_connections_unauth: AtomicU32::new(max_connections_unauth.unwrap_or(0)),
            ip_connections: Arc::new(RwLock::new(HashMap::new())),
            unauth_connections: Arc::new(AtomicU32::new(0)),
            stats,
        })
    }

    /// Hot-reloads rate limits, quotas, and connection limits from reloaded configuration (e.g. on SIGHUP).
    /// Preserves existing accumulated tenant usage and active connection counts.
    pub fn reload(
        &self,
        network_bandwidth: Option<&str>,
        max_connections: Option<u32>,
        max_connections_per_ip: Option<u32>,
        max_connections_unauth: Option<u32>,
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
        let mut new_soft_quota_map = HashMap::new();

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
                let soft = if let Some(ref sq) = limit_cfg.soft_quota_bytes {
                    parse_rate_limit(sq).map_err(|e| {
                        anyhow::anyhow!(
                            "invalid soft_quota_bytes '{sq}' for identity '{ident}': {e}"
                        )
                    })?
                } else {
                    (quota as f64 * 0.9) as u64
                };
                new_quota_map.insert(ident.clone(), quota);
                new_soft_quota_map.insert(ident, soft);
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
        if let Ok(mut sq) = self.soft_quotas.write() {
            *sq = new_soft_quota_map;
        }

        if let Some(m) = max_connections {
            self.max_connections.store(m, Ordering::Relaxed);
        }
        if let Some(m) = max_connections_per_ip {
            self.max_connections_per_ip.store(m, Ordering::Relaxed);
        }
        if let Some(m) = max_connections_unauth {
            self.max_connections_unauth.store(m, Ordering::Relaxed);
        }

        info!("reloaded bandwidth limits, tenant quotas, and connection ceilings on SIGHUP");
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

    /// Check connection limits across global ceiling, per-IP ceiling, and unauthenticated ceiling.
    /// Returns an RAII `ConnectionGuard` on success.
    pub fn check_connection_limits(
        &self,
        remote_ip: std::net::IpAddr,
        current_active: u64,
    ) -> Result<ConnectionGuard, String> {
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

        let max_per_ip = self.max_connections_per_ip.load(Ordering::Relaxed);
        if max_per_ip > 0 {
            if let Ok(map) = self.ip_connections.read() {
                let count = map.get(&remote_ip).copied().unwrap_or(0);
                if count >= max_per_ip {
                    self.stats
                        .resource_limit_hits_connections
                        .fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .resource_limit_hits
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(format!(
                        "per-IP connection limit reached for {remote_ip} ({count} >= {max_per_ip})"
                    ));
                }
            }
        }

        let max_unauth = self.max_connections_unauth.load(Ordering::Relaxed);
        if max_unauth > 0 {
            let unauth = self.unauth_connections.load(Ordering::Relaxed);
            if unauth >= max_unauth {
                self.stats
                    .resource_limit_hits_connections
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .resource_limit_hits
                    .fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "unauthenticated connection limit reached ({unauth} >= {max_unauth})"
                ));
            }
        }

        if let Ok(mut map) = self.ip_connections.write() {
            *map.entry(remote_ip).or_insert(0) += 1;
        }
        self.unauth_connections.fetch_add(1, Ordering::SeqCst);

        Ok(ConnectionGuard {
            ip: remote_ip,
            ip_connections: Arc::clone(&self.ip_connections),
            unauth_connections: Arc::clone(&self.unauth_connections),
            is_unauth: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        })
    }

    /// Return active connections for a given IP.
    pub fn active_ip_connections(&self, ip: std::net::IpAddr) -> u32 {
        self.ip_connections
            .read()
            .ok()
            .and_then(|m| m.get(&ip).copied())
            .unwrap_or(0)
    }

    /// Return active unauthenticated connections.
    pub fn active_unauth_connections(&self) -> u32 {
        self.unauth_connections.load(Ordering::Relaxed)
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

    /// Return the active quota reservations for a tenant in bytes.
    pub fn get_reserved(&self, identity: &str) -> u64 {
        self.reservations
            .read()
            .ok()
            .and_then(|r| r.get(identity).copied())
            .unwrap_or(0)
    }

    /// Return the soft quota for a tenant in bytes (if any).
    pub fn get_soft_quota(&self, identity: &str) -> Option<u64> {
        self.soft_quotas
            .read()
            .ok()
            .and_then(|q| q.get(identity).copied())
    }

    /// Atomically check and reserve transfer quota for `identity`.
    /// Returns an RAII `QuotaReservation` on success.
    pub fn reserve_quota(
        &self,
        identity: Option<&str>,
        additional_bytes: u64,
    ) -> Result<QuotaReservation, String> {
        let Some(ident) = identity else {
            return Ok(QuotaReservation {
                identity: None,
                bytes: additional_bytes,
                committed: false,
                reservations: Arc::clone(&self.reservations),
                usage: Arc::clone(&self.usage),
            });
        };

        let quotas = match self.quotas.read() {
            Ok(g) => g,
            Err(_) => return Err("limits manager lock poisoned".into()),
        };

        if let Some(&hard_quota) = quotas.get(ident) {
            let usage_map = match self.usage.read() {
                Ok(g) => g,
                Err(_) => return Err("limits manager lock poisoned".into()),
            };
            let current_usage = usage_map.get(ident).copied().unwrap_or(0);
            drop(usage_map);

            let mut res_map = match self.reservations.write() {
                Ok(g) => g,
                Err(_) => return Err("limits manager lock poisoned".into()),
            };
            let current_res = res_map.get(ident).copied().unwrap_or(0);

            let total_projected = current_usage
                .saturating_add(current_res)
                .saturating_add(additional_bytes);

            if total_projected > hard_quota {
                self.stats
                    .resource_limit_hits_quota
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .resource_limit_hits
                    .fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "tenant '{ident}' quota exceeded (used {current_usage} + reserved {current_res} + requested {additional_bytes} > {hard_quota})"
                ));
            }

            // Check soft quota warning
            if let Ok(soft_map) = self.soft_quotas.read() {
                let soft = soft_map
                    .get(ident)
                    .copied()
                    .unwrap_or((hard_quota as f64 * 0.9) as u64);
                if total_projected > soft {
                    tracing::warn!(
                        tenant = ident,
                        projected = total_projected,
                        soft_quota = soft,
                        hard_quota = hard_quota,
                        "tenant approaching quota limit (soft quota threshold exceeded)"
                    );
                }
            }

            *res_map.entry(ident.to_string()).or_insert(0) += additional_bytes;
        }

        Ok(QuotaReservation {
            identity: Some(ident.to_string()),
            bytes: additional_bytes,
            committed: false,
            reservations: Arc::clone(&self.reservations),
            usage: Arc::clone(&self.usage),
        })
    }

    /// Record a delta in tenant cumulative stored bytes.
    pub fn record_storage_delta(&self, identity: &str, delta_bytes: i64) {
        if let Ok(mut map) = self.tenant_storage_bytes.write() {
            let entry = map.entry(identity.to_string()).or_insert(0);
            if delta_bytes >= 0 {
                *entry = entry.saturating_add(delta_bytes as u64);
            } else {
                *entry = entry.saturating_sub((-delta_bytes) as u64);
            }
        }
    }

    /// Return total recorded storage bytes for a tenant.
    pub fn get_storage_usage(&self, identity: &str) -> u64 {
        self.tenant_storage_bytes
            .read()
            .ok()
            .and_then(|m| m.get(identity).copied())
            .unwrap_or(0)
    }

    /// Reconcile tenant storage bytes by scanning their directory tree.
    pub fn reconcile_tenant_storage<P: AsRef<std::path::Path>>(
        &self,
        identity: &str,
        path: P,
    ) -> std::io::Result<u64> {
        fn dir_size(p: &std::path::Path) -> std::io::Result<u64> {
            if !p.exists() {
                return Ok(0);
            }
            let mut total = 0u64;
            if p.is_file() {
                return Ok(p.metadata()?.len());
            }
            for entry in std::fs::read_dir(p)? {
                let entry = entry?;
                let meta = entry.metadata()?;
                if meta.is_dir() {
                    total += dir_size(&entry.path())?;
                } else {
                    total += meta.len();
                }
            }
            Ok(total)
        }

        let total = dir_size(path.as_ref())?;
        if let Ok(mut map) = self.tenant_storage_bytes.write() {
            map.insert(identity.to_string(), total);
        }
        Ok(total)
    }

    /// Check whether a tenant with `identity` has sufficient quota for `additional_bytes`.
    pub fn check_quota(&self, identity: Option<&str>, additional_bytes: u64) -> Result<(), String> {
        <Self as LimitsProvider>::check_quota(self, identity, additional_bytes)
    }

    /// Record committed bytes to a tenant's quota usage.
    pub fn record_transfer(&self, identity: Option<&str>, bytes_committed: u64) {
        <Self as LimitsProvider>::record_transfer(self, identity, bytes_committed);
    }

    /// Return a snapshot list of all known tenants and their quota / bandwidth utilization.
    pub fn list_tenants_quotas(&self) -> Vec<TenantQuotaInfo> {
        let mut idents = std::collections::BTreeSet::new();
        if let Ok(g) = self.quotas.read() {
            idents.extend(g.keys().cloned());
        }
        if let Ok(g) = self.usage.read() {
            idents.extend(g.keys().cloned());
        }
        if let Ok(g) = self.tenant_storage_bytes.read() {
            idents.extend(g.keys().cloned());
        }
        if let Ok(g) = self.tenant_limiters.read() {
            idents.extend(g.keys().cloned());
        }

        let mut res = Vec::new();
        for id in idents {
            let quota_bytes = self.get_quota(&id);
            let soft_quota_bytes = self.get_soft_quota(&id);
            let transfer_usage_bytes = self.get_usage(&id);
            let reserved_bytes = self.get_reserved(&id);
            let storage_usage_bytes = self.get_storage_usage(&id);
            let max_bandwidth_bps = self.tenant_bandwidth(&id);

            res.push(TenantQuotaInfo {
                identity: id,
                quota_bytes,
                soft_quota_bytes,
                transfer_usage_bytes,
                reserved_bytes,
                storage_usage_bytes,
                max_bandwidth_bps,
            });
        }
        res
    }
}

/// Tenant quota and usage snapshot for administrative inspection (`REQUIREMENTS.md` §23, §81).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TenantQuotaInfo {
    pub identity: String,
    pub quota_bytes: Option<u64>,
    pub soft_quota_bytes: Option<u64>,
    pub transfer_usage_bytes: u64,
    pub reserved_bytes: u64,
    pub storage_usage_bytes: u64,
    pub max_bandwidth_bps: Option<u64>,
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
            let reservations = match self.reservations.read() {
                Ok(g) => g,
                Err(_) => return Ok(()),
            };
            let current = usage.get(ident).copied().unwrap_or(0);
            let reserved = reservations.get(ident).copied().unwrap_or(0);
            if current
                .saturating_add(reserved)
                .saturating_add(additional_bytes)
                > quota
            {
                self.stats
                    .resource_limit_hits_quota
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .resource_limit_hits
                    .fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "tenant '{ident}' quota exceeded (used {current} + reserved {reserved} + {additional_bytes} > {quota})"
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
