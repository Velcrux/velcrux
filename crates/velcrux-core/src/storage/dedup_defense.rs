//! Multi-Tenant Dedup Poisoning Defense & Namespacing (Option BJ).
//!
//! Implements defenses against deduplication poisoning, content existence oracles,
//! and unauthorized cross-tenant chunk reading (`CLAUDE.md` §4 Open Questions #3 & #4,
//! `SECURITY.md` §8 & §9, `ADR-026`).

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::chunk_store::{ChunkStore, LocalChunkStore};
use crate::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use crate::error::{ProtocolError, VelcruxError};
use crate::sync::BloomFilter;
use crate::util::Hash;

/// Multi-tenant deduplication namespacing policy (`CLAUDE.md` §4, `ADR-026`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupNamespacePolicy {
    /// Strict physical tenant isolation. Each tenant has their own isolated chunk store
    /// partitioned by tenant identity (`<root>/tenants/<tenant_id>/chunks/...`).
    /// Cross-tenant chunk lookups and content existence oracles are physically impossible.
    Isolated,
    /// Convergent deduplication across tenants gated on cryptographic Proof of Ownership (PoW).
    /// Prevents content existence oracles and poisoning by requiring proof that the client
    /// actually possesses chunk data before granting deduplication reuse.
    ProofOfOwnership,
    /// Global shared deduplication without tenant barriers (legacy single-tenant mode).
    Global,
}

impl Default for DedupNamespacePolicy {
    fn default() -> Self {
        Self::Isolated
    }
}

impl fmt::Display for DedupNamespacePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Isolated => write!(f, "isolated"),
            Self::ProofOfOwnership => write!(f, "proof_of_ownership"),
            Self::Global => write!(f, "global"),
        }
    }
}

impl FromStr for DedupNamespacePolicy {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let norm = s.trim().to_lowercase().replace('_', "-");
        match norm.as_str() {
            "isolated" | "tenant" | "per-tenant" => Ok(Self::Isolated),
            "proof" | "pow" | "proof-of-ownership" | "convergent" => Ok(Self::ProofOfOwnership),
            "global" | "shared" => Ok(Self::Global),
            _other => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid dedup namespace policy",
            ))),
        }
    }
}

/// Cryptographic Proof-of-Ownership (PoW) engine.
///
/// Prevents content existence oracles by proving that the client possesses the full chunk data,
/// not merely its hash. Computed as a BLAKE3 keyed hash over chunk hash and contents.
#[derive(Debug, Clone)]
pub struct ProofOfOwnershipEngine {
    server_key: [u8; 32],
}

impl ProofOfOwnershipEngine {
    /// Create a new PoW engine with the specified 32-byte server secret.
    pub fn new(server_key: [u8; 32]) -> Self {
        Self { server_key }
    }

    /// Generate an ephemeral random server key.
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        for b in &mut key {
            *b = rand::random::<u8>();
        }
        Self { server_key: key }
    }

    /// Server secret key bytes.
    #[inline]
    pub fn key(&self) -> &[u8; 32] {
        &self.server_key
    }

    /// Compute expected Proof-of-Ownership token for a given chunk hash and data payload.
    ///
    /// Token = BLAKE3-KeyedHash(server_key, hash || data)
    pub fn compute_token(&self, chunk_hash: &Hash, chunk_data: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.server_key);
        hasher.update(chunk_hash.as_bytes());
        hasher.update(chunk_data);
        *hasher.finalize().as_bytes()
    }

    /// Verify whether a submitted PoW token matches the expected token for `chunk_hash` and `chunk_data`.
    pub fn verify_token(&self, chunk_hash: &Hash, chunk_data: &[u8], token: &[u8; 32]) -> bool {
        let expected = self.compute_token(chunk_hash, chunk_data);
        // Constant-time comparison
        subtle_slice_eq(&expected, token)
    }
}

/// Constant-time slice comparison to prevent timing side channels.
#[inline]
fn subtle_slice_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Access Control List (ACL) entry tracking chunk ownership and provenance in shared modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAclEntry {
    /// Primary tenant identity that originally uploaded this chunk.
    pub owner_tenant: String,
    /// Set of tenant identities that have proved ownership of this chunk.
    pub authorized_tenants: HashSet<String>,
    /// Timestamp when this chunk was first stored.
    pub created_at: u64,
    /// Timestamp when this chunk was last successfully accessed or referenced.
    pub last_accessed_at: u64,
    /// Total reference / reuse count.
    pub access_count: u64,
}

impl ChunkAclEntry {
    /// Create a new ACL entry owned by `tenant_id`.
    pub fn new(tenant_id: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut auth = HashSet::new();
        auth.insert(tenant_id.to_string());
        Self {
            owner_tenant: tenant_id.to_string(),
            authorized_tenants: auth,
            created_at: now,
            last_accessed_at: now,
            access_count: 1,
        }
    }

    /// Check whether `tenant_id` is authorized to access or deduplicate against this chunk.
    pub fn is_authorized(&self, tenant_id: &str) -> bool {
        if self.owner_tenant == tenant_id {
            return true;
        }
        self.authorized_tenants.contains(tenant_id)
    }

    /// Grant authorization to `tenant_id` after valid Proof-of-Ownership verification.
    pub fn authorize_tenant(&mut self, tenant_id: &str) {
        self.authorized_tenants.insert(tenant_id.to_string());
        self.record_access();
    }

    /// Record chunk access event.
    pub fn record_access(&mut self) {
        self.last_accessed_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.access_count = self.access_count.saturating_add(1);
    }
}

/// Information regarding a quarantined chunk that failed integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedChunk {
    pub hash: Hash,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub reason: String,
    pub quarantined_at: u64,
    pub file_size: u64,
}

/// Quarantine manager for poisoned or corrupted chunks (`ADR-026`).
#[derive(Debug)]
pub struct ChunkQuarantineManager {
    quarantine_dir: PathBuf,
    records: RwLock<HashMap<Hash, QuarantinedChunk>>,
}

impl ChunkQuarantineManager {
    /// Create a new quarantine manager at `quarantine_dir`.
    pub fn new<P: AsRef<Path>>(quarantine_dir: P) -> Result<Self, VelcruxError> {
        let dir = quarantine_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            quarantine_dir: dir,
            records: RwLock::new(HashMap::new()),
        })
    }

    /// Isolate a corrupted chunk into the quarantine directory.
    pub fn quarantine(&self, hash: &Hash, file_path: &Path, reason: &str) -> Result<PathBuf, VelcruxError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let target_name = format!("{}_{}_{}.quarantine", hash, now, rand::random::<u32>());
        let target_path = self.quarantine_dir.join(target_name);

        let file_size = file_path.metadata().map(|m| m.len()).unwrap_or(0);
        if file_path.exists() {
            fs::rename(file_path, &target_path)?;
        }

        let record = QuarantinedChunk {
            hash: *hash,
            original_path: file_path.to_path_buf(),
            quarantine_path: target_path.clone(),
            reason: reason.to_string(),
            quarantined_at: now,
            file_size,
        };

        if let Ok(mut map) = self.records.write() {
            map.insert(*hash, record);
        }

        Ok(target_path)
    }

    /// List all currently quarantined chunks.
    pub fn list(&self) -> Vec<QuarantinedChunk> {
        self.records
            .read()
            .ok()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Remove all quarantined files from disk.
    pub fn purge(&self) -> Result<usize, VelcruxError> {
        let mut count = 0;
        if let Ok(mut map) = self.records.write() {
            for (_, record) in map.drain() {
                if record.quarantine_path.exists() {
                    let _ = fs::remove_file(&record.quarantine_path);
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}

/// High-level namespaced chunk store coordinating multi-tenant deduplication and poisoning defense.
pub struct NamespacedChunkStore {
    root: PathBuf,
    policy: DedupNamespacePolicy,
    pow_engine: ProofOfOwnershipEngine,
    quarantine: ChunkQuarantineManager,
    /// Cached per-tenant chunk stores for `Isolated` policy.
    tenant_stores: RwLock<HashMap<String, Arc<LocalChunkStore>>>,
    /// Shared global chunk store for `ProofOfOwnership` or `Global` policy.
    shared_store: Arc<LocalChunkStore>,
    /// Chunk access control table for `ProofOfOwnership` policy.
    acl_table: RwLock<HashMap<Hash, ChunkAclEntry>>,
    /// Metric counters for security monitoring.
    poison_attempts: std::sync::atomic::AtomicU64,
    oracle_probes_blocked: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for NamespacedChunkStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamespacedChunkStore")
            .field("root", &self.root)
            .field("policy", &self.policy)
            .finish()
    }
}

impl NamespacedChunkStore {
    /// Initialize a new namespaced chunk store with given policy and root directory.
    pub async fn new<P: AsRef<Path>>(
        root: P,
        policy: DedupNamespacePolicy,
        server_secret: Option<[u8; 32]>,
    ) -> Result<Self, VelcruxError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;

        let quarantine_dir = root.join(".quarantine");
        let quarantine = ChunkQuarantineManager::new(quarantine_dir)?;

        let shared_dir = root.join("shared");
        let shared_store = Arc::new(LocalChunkStore::new(&shared_dir).await?);

        let pow_engine = match server_secret {
            Some(key) => ProofOfOwnershipEngine::new(key),
            None => ProofOfOwnershipEngine::random(),
        };

        Ok(Self {
            root,
            policy,
            pow_engine,
            quarantine,
            tenant_stores: RwLock::new(HashMap::new()),
            shared_store,
            acl_table: RwLock::new(HashMap::new()),
            poison_attempts: std::sync::atomic::AtomicU64::new(0),
            oracle_probes_blocked: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Configured deduplication namespace policy.
    #[inline]
    pub fn policy(&self) -> DedupNamespacePolicy {
        self.policy
    }

    /// Root storage directory.
    #[inline]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Proof-of-ownership engine reference.
    #[inline]
    pub fn pow_engine(&self) -> &ProofOfOwnershipEngine {
        &self.pow_engine
    }

    /// Shared chunk store reference.
    #[inline]
    pub fn shared_store(&self) -> &Arc<LocalChunkStore> {
        &self.shared_store
    }

    /// Quarantine manager reference.
    #[inline]
    pub fn quarantine(&self) -> &ChunkQuarantineManager {
        &self.quarantine
    }

    /// Total detected deduplication poisoning attempts.
    #[inline]
    pub fn poison_attempts(&self) -> u64 {
        self.poison_attempts.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total cross-tenant existence oracle probing attempts blocked.
    #[inline]
    pub fn oracle_probes_blocked(&self) -> u64 {
        self.oracle_probes_blocked.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Resolve or lazily instantiate the isolated `LocalChunkStore` for a tenant.
    pub async fn get_tenant_store(&self, tenant_id: &str) -> Result<Arc<LocalChunkStore>, VelcruxError> {
        if self.policy != DedupNamespacePolicy::Isolated {
            return Ok(Arc::clone(&self.shared_store));
        }

        let clean_tenant = sanitize_tenant_id(tenant_id);
        if let Ok(map) = self.tenant_stores.read() {
            if let Some(store) = map.get(&clean_tenant) {
                return Ok(Arc::clone(store));
            }
        }

        let tenant_dir = self.root.join("tenants").join(&clean_tenant);
        let store = Arc::new(LocalChunkStore::new(&tenant_dir).await?);
        if let Ok(mut map) = self.tenant_stores.write() {
            let entry = map.entry(clean_tenant).or_insert_with(|| Arc::clone(&store));
            Ok(Arc::clone(entry))
        } else {
            Ok(store)
        }
    }

    /// Synchronously check whether a chunk exists and is authorized for `tenant_id`.
    ///
    /// In `Isolated` mode: evaluates exclusively within the tenant's isolated repository.
    /// In `ProofOfOwnership` mode: evaluates within the shared store only if `tenant_id` is authorized in the ACL.
    /// In `Global` mode: evaluates globally across the store.
    pub fn contains_for_tenant(&self, tenant_id: &str, h: &Hash) -> bool {
        match self.policy {
            DedupNamespacePolicy::Isolated => {
                let clean_tenant = sanitize_tenant_id(tenant_id);
                if let Ok(map) = self.tenant_stores.read() {
                    if let Some(store) = map.get(&clean_tenant) {
                        return store.contains_sync(h);
                    }
                }
                // Check if directory exists on disk even if not in memory cache
                let tenant_dir = self.root.join("tenants").join(&clean_tenant);
                let hex = h.to_string();
                let path = tenant_dir
                    .join("chunks")
                    .join(&hex[0..2])
                    .join(&hex[2..4])
                    .join(format!("{hex}.chunk"));
                if path.exists() {
                    return true;
                }
                if let Ok(map) = self.tenant_stores.read() {
                    let in_other_tenant = map.iter().any(|(t, s)| t != &clean_tenant && s.contains_sync(h));
                    if in_other_tenant || self.shared_store.contains_sync(h) {
                        self.oracle_probes_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                false
            }
            DedupNamespacePolicy::ProofOfOwnership => {
                if !self.shared_store.contains_sync(h) {
                    return false;
                }
                if let Ok(acl) = self.acl_table.read() {
                    if let Some(entry) = acl.get(h) {
                        if entry.is_authorized(tenant_id) {
                            return true;
                        }
                    }
                }
                // Exists in shared store, but tenant is not authorized yet
                self.oracle_probes_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }
            DedupNamespacePolicy::Global => self.shared_store.contains_sync(h),
        }
    }

    /// Verify a client's Proof-of-Ownership for a chunk.
    ///
    /// If valid, records `tenant_id` into the chunk's ACL table, enabling deduplication reuse.
    pub fn verify_and_authorize_pow(
        &self,
        tenant_id: &str,
        chunk_hash: &Hash,
        chunk_data: &[u8],
        token: &[u8; 32],
    ) -> bool {
        if !self.pow_engine.verify_token(chunk_hash, chunk_data, token) {
            self.poison_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }

        if let Ok(mut acl) = self.acl_table.write() {
            let entry = acl.entry(*chunk_hash).or_insert_with(|| ChunkAclEntry::new(tenant_id));
            entry.authorize_tenant(tenant_id);
        }
        true
    }

    /// Copy a verified chunk directly into `dst_file` for `tenant_id`.
    /// Performs in-flight BLAKE3 verification and quarantines poisoned/corrupted chunks.
    pub fn copy_chunk_for_tenant(
        &self,
        tenant_id: &str,
        h: &Hash,
        dst_file: &mut File,
        dst_offset: u64,
    ) -> Result<u64, VelcruxError> {
        let clean_tenant = sanitize_tenant_id(tenant_id);

        let (_store, chunk_path) = match self.policy {
            DedupNamespacePolicy::Isolated => {
                let tenant_dir = self.root.join("tenants").join(&clean_tenant);
                let hex = h.to_string();
                let path = tenant_dir
                    .join("chunks")
                    .join(&hex[0..2])
                    .join(&hex[2..4])
                    .join(format!("{hex}.chunk"));
                (None, path)
            }
            DedupNamespacePolicy::ProofOfOwnership => {
                // Verify authorization first
                if let Ok(acl) = self.acl_table.read() {
                    if let Some(entry) = acl.get(h) {
                        if !entry.is_authorized(tenant_id) {
                            self.oracle_probes_blocked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                                "unauthorized access to chunk in shared store",
                            )));
                        }
                    } else {
                        return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                            "chunk not authorized for tenant",
                        )));
                    }
                }
                (Some(Arc::clone(&self.shared_store)), self.shared_store.chunk_path(h))
            }
            DedupNamespacePolicy::Global => {
                (Some(Arc::clone(&self.shared_store)), self.shared_store.chunk_path(h))
            }
        };

        if !chunk_path.exists() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "chunk not found in store",
            )));
        }

        let mut chunk_file = File::open(&chunk_path)?;
        let chunk_len = chunk_file.metadata()?.len();
        dst_file.seek(SeekFrom::Start(dst_offset))?;

        let mut buf = [0u8; 64 * 1024];
        let mut remaining = chunk_len;
        let mut hasher = blake3::Hasher::new();

        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = chunk_file.read(&mut buf[..to_read])?;
            if n == 0 {
                // Poisoning / corruption detected: truncated chunk
                let _ = self.quarantine.quarantine(h, &chunk_path, "truncated chunk payload");
                self.poison_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "checksum mismatch: truncated chunk quarantined",
                )));
            }
            hasher.update(&buf[..n]);
            dst_file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }

        let computed = Hash::from_bytes(hasher.finalize().as_bytes()).unwrap();
        if computed != *h {
            // Poisoning detected: content does not match hash! Quarantine immediately.
            let _ = self.quarantine.quarantine(h, &chunk_path, "blake3_checksum_mismatch: checksum mismatch");
            self.poison_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "checksum mismatch: poisoned chunk quarantined",
            )));
        }

        if let Ok(mut acl) = self.acl_table.write() {
            if let Some(entry) = acl.get_mut(h) {
                entry.record_access();
            }
        }

        Ok(chunk_len)
    }

    /// Authorize a tenant to access an existing chunk in Proof-of-Ownership mode.
    ///
    /// Requires client to present a valid PoW token computed using the server secret.
    pub fn authorize_tenant_with_pow(&self, tenant_id: &str, h: &Hash, token: &[u8; 32]) -> bool {
        if self.policy != DedupNamespacePolicy::ProofOfOwnership {
            return false;
        }
        if let Ok(data) = self.shared_store.get_sync(h) {
            if self.pow_engine.verify_token(h, &data, token) {
                if let Ok(mut acl) = self.acl_table.write() {
                    let entry = acl.entry(*h).or_insert_with(|| ChunkAclEntry::new(tenant_id));
                    entry.authorize_tenant(tenant_id);
                    return true;
                }
            }
        }
        false
    }

    /// Store a verified chunk into the appropriate namespace for `tenant_id`.
    pub async fn put_for_tenant(
        &self,
        tenant_id: &str,
        h: &Hash,
        data: &[u8],
    ) -> Result<(), VelcruxError> {
        let computed = Hash::of(data);
        if computed != *h {
            self.poison_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "checksum mismatch: rejected corrupted chunk put",
            )));
        }

        match self.policy {
            DedupNamespacePolicy::Isolated => {
                let store = self.get_tenant_store(tenant_id).await?;
                store.put(h, data).await
            }
            DedupNamespacePolicy::ProofOfOwnership => {
                self.shared_store.put(h, data).await?;
                if let Ok(mut acl) = self.acl_table.write() {
                    let entry = acl.entry(*h).or_insert_with(|| ChunkAclEntry::new(tenant_id));
                    entry.authorize_tenant(tenant_id);
                }
                Ok(())
            }
            DedupNamespacePolicy::Global => self.shared_store.put(h, data).await,
        }
    }

    /// Ingest a committed file into the tenant's chunk store namespace.
    pub async fn ingest_file_for_tenant<P: AsRef<Path>>(
        &self,
        tenant_id: &str,
        path: P,
        mode: ChunkMode,
        params: ChunkParams,
    ) -> Result<usize, VelcruxError> {
        match self.policy {
            DedupNamespacePolicy::Isolated => {
                let store = self.get_tenant_store(tenant_id).await?;
                store.ingest_file_sync(path, mode, params)
            }
            DedupNamespacePolicy::ProofOfOwnership => {
                let count = self.shared_store.ingest_file_sync(&path, mode, params)?;
                // Authorize tenant for all chunks in the file
                let file = File::open(&path)?;
                let reader = std::io::BufReader::with_capacity(params.max.max(64 * 1024) as usize, file);
                let acl_table = &self.acl_table;
                ChunkEngine::chunk_reader(reader, mode, params, params.max as usize, |desc, _| {
                    if let Some(hash) = desc.hash {
                        if let Ok(mut acl) = acl_table.write() {
                            let entry = acl.entry(hash).or_insert_with(|| ChunkAclEntry::new(tenant_id));
                            entry.authorize_tenant(tenant_id);
                        }
                    }
                    Ok(())
                })?;
                Ok(count)
            }
            DedupNamespacePolicy::Global => self.shared_store.ingest_file_sync(path, mode, params),
        }
    }

    /// Return Bloom filter appropriate for `tenant_id`.
    pub async fn bloom_filter_for_tenant(&self, tenant_id: &str) -> Result<BloomFilter, VelcruxError> {
        match self.policy {
            DedupNamespacePolicy::Isolated => {
                let store = self.get_tenant_store(tenant_id).await?;
                Ok(store.bloom_filter())
            }
            DedupNamespacePolicy::ProofOfOwnership => {
                // In ProofOfOwnership mode, only return bloom filter containing chunks
                // already authorized for this tenant, preventing existence leakage!
                let mut b = BloomFilter::new(50_000, 0.01);
                if let Ok(acl) = self.acl_table.read() {
                    for (h, entry) in acl.iter() {
                        if entry.is_authorized(tenant_id) {
                            b.insert(h);
                        }
                    }
                }
                Ok(b)
            }
            DedupNamespacePolicy::Global => Ok(self.shared_store.bloom_filter()),
        }
    }

    /// Audit and verify the integrity of all chunks across all namespaces.
    /// Quarantines any poisoned or corrupted chunks found and returns a report.
    pub fn verify_integrity_sweep(&self) -> Result<DedupAuditReport, VelcruxError> {
        let mut report = DedupAuditReport::default();

        let mut paths_to_scan = Vec::new();

        // 1. Scan shared store
        let shared_chunks = self.shared_store.chunks_dir();
        if shared_chunks.exists() {
            collect_chunk_files(shared_chunks, &mut paths_to_scan);
        }

        // 2. Scan all tenant stores
        let tenants_root = self.root.join("tenants");
        if tenants_root.exists() {
            if let Ok(entries) = fs::read_dir(&tenants_root) {
                for entry in entries.flatten() {
                    let tenant_chunks = entry.path().join("chunks");
                    if tenant_chunks.exists() {
                        collect_chunk_files(&tenant_chunks, &mut paths_to_scan);
                    }
                }
            }
        }

        report.total_chunks_scanned = paths_to_scan.len();

        for chunk_path in paths_to_scan {
            let filename = chunk_path.file_name().unwrap().to_str().unwrap();
            let hash_str = filename.strip_suffix(".chunk").unwrap_or(filename);
            let expected_hash = match Hash::from_hex(hash_str) {
                Some(h) => h,
                None => {
                    report.corrupt_chunks_quarantined += 1;
                    continue;
                }
            };

            let mut f = match File::open(&chunk_path) {
                Ok(file) => file,
                Err(_) => continue,
            };

            let mut data = Vec::new();
            if f.read_to_end(&mut data).is_err() {
                let _ = self.quarantine.quarantine(&expected_hash, &chunk_path, "I/O read failure");
                report.corrupt_chunks_quarantined += 1;
                continue;
            }

            let computed = Hash::of(&data);
            if computed != expected_hash {
                let _ = self.quarantine.quarantine(
                    &expected_hash,
                    &chunk_path,
                    "Cryptographic BLAKE3 checksum mismatch (Poisoning Detected)",
                );
                report.corrupt_chunks_quarantined += 1;
                report.poison_attacks_neutralized += 1;
            } else {
                report.valid_chunks += 1;
                report.total_bytes_verified += data.len() as u64;
            }
        }

        Ok(report)
    }
}

/// Helper to sanitize tenant identifiers to prevent filesystem directory traversal.
fn sanitize_tenant_id(tenant_id: &str) -> String {
    let trimmed = tenant_id.trim();
    if trimmed.is_empty() {
        return "default".to_string();
    }
    let sanitized: String = trimmed
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "default".to_string()
    } else {
        sanitized
    }
}

/// Recursive helper to collect chunk files with `.chunk` suffix.
fn collect_chunk_files(dir: &Path, acc: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_chunk_files(&path, acc);
            } else if path.extension().and_then(|s| s.to_str()) == Some("chunk") {
                acc.push(path);
            }
        }
    }
}

/// Report summarizing the results of a deduplication integrity audit sweep.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DedupAuditReport {
    pub total_chunks_scanned: usize,
    pub valid_chunks: usize,
    pub corrupt_chunks_quarantined: usize,
    pub poison_attacks_neutralized: usize,
    pub total_bytes_verified: u64,
}

/// Type alias for deduplication audit / poison neutralization report.
pub type ChunkPoisonReport = DedupAuditReport;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_namespace_policy_parsing() {
        assert_eq!("isolated".parse::<DedupNamespacePolicy>().unwrap(), DedupNamespacePolicy::Isolated);
        assert_eq!("tenant".parse::<DedupNamespacePolicy>().unwrap(), DedupNamespacePolicy::Isolated);
        assert_eq!("proof".parse::<DedupNamespacePolicy>().unwrap(), DedupNamespacePolicy::ProofOfOwnership);
        assert_eq!("proof_of_ownership".parse::<DedupNamespacePolicy>().unwrap(), DedupNamespacePolicy::ProofOfOwnership);
        assert_eq!("global".parse::<DedupNamespacePolicy>().unwrap(), DedupNamespacePolicy::Global);
        assert!("invalid".parse::<DedupNamespacePolicy>().is_err());
    }

    #[test]
    fn test_proof_of_ownership_verification() {
        let engine = ProofOfOwnershipEngine::random();
        let chunk_data = b"confidential enterprise dataset segment 12345";
        let chunk_hash = Hash::of(chunk_data);

        let token = engine.compute_token(&chunk_hash, chunk_data);
        assert!(engine.verify_token(&chunk_hash, chunk_data, &token));

        // Wrong data fails
        let wrong_data = b"tampered data";
        assert!(!engine.verify_token(&chunk_hash, wrong_data, &token));

        // Wrong token fails
        let mut tampered_token = token;
        tampered_token[0] ^= 0xff;
        assert!(!engine.verify_token(&chunk_hash, chunk_data, &tampered_token));
    }

    #[tokio::test]
    async fn test_isolated_namespacing_prevents_cross_tenant_leak() {
        let temp = tempfile::tempdir().unwrap();
        let store = NamespacedChunkStore::new(
            temp.path(),
            DedupNamespacePolicy::Isolated,
            None,
        )
        .await
        .unwrap();

        let data = b"Tenant A secret document chunk";
        let hash = Hash::of(data);

        // Tenant A stores chunk
        store.put_for_tenant("tenant-a", &hash, data).await.unwrap();

        // Tenant A has it
        assert!(store.contains_for_tenant("tenant-a", &hash));

        // Tenant B DOES NOT have it (strict isolation, no existence oracle!)
        assert!(!store.contains_for_tenant("tenant-b", &hash));

        // Tenant B cannot copy it
        let mut dst = tempfile::tempfile().unwrap();
        let res = store.copy_chunk_for_tenant("tenant-b", &hash, &mut dst, 0);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_pow_mode_gates_cross_tenant_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let secret = [42u8; 32];
        let store = NamespacedChunkStore::new(
            temp.path(),
            DedupNamespacePolicy::ProofOfOwnership,
            Some(secret),
        )
        .await
        .unwrap();

        let data = b"Shared dataset common layer";
        let hash = Hash::of(data);

        // Tenant A stores chunk
        store.put_for_tenant("tenant-a", &hash, data).await.unwrap();

        // Before PoW, Tenant B is denied
        assert!(!store.contains_for_tenant("tenant-b", &hash));

        // Tenant B computes valid PoW
        let token = store.pow_engine().compute_token(&hash, data);
        assert!(store.verify_and_authorize_pow("tenant-b", &hash, data, &token));

        // Now Tenant B is authorized to reuse it
        assert!(store.contains_for_tenant("tenant-b", &hash));

        let mut dst = tempfile::tempfile().unwrap();
        let copied = store.copy_chunk_for_tenant("tenant-b", &hash, &mut dst, 0).unwrap();
        assert_eq!(copied, data.len() as u64);
    }

    #[tokio::test]
    async fn test_quarantine_corrupted_chunk_poisoning() {
        let temp = tempfile::tempdir().unwrap();
        let store = NamespacedChunkStore::new(
            temp.path(),
            DedupNamespacePolicy::Global,
            None,
        )
        .await
        .unwrap();

        let data = b"Legitimate chunk payload";
        let hash = Hash::of(data);

        store.put_for_tenant("global", &hash, data).await.unwrap();

        // Simulate disk bit-rot / malicious poisoning attack by mutating the file on disk
        let chunk_path = store.shared_store.chunk_path(&hash);
        fs::write(&chunk_path, b"POISONED TAMPERED CONTENT!").unwrap();

        // Attempting to copy chunk should detect checksum mismatch, quarantine the poisoned file, and return an error
        let mut dst = tempfile::tempfile().unwrap();
        let res = store.copy_chunk_for_tenant("global", &hash, &mut dst, 0);
        assert!(res.is_err());

        // File should have been moved into quarantine!
        assert!(!chunk_path.exists());
        let quarantined = store.quarantine().list();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].hash, hash);
        assert!(quarantined[0].reason.contains("checksum mismatch"));

        // Audit report catches it
        let audit = store.verify_integrity_sweep().unwrap();
        assert_eq!(audit.corrupt_chunks_quarantined, 0); // Already moved
    }
}
