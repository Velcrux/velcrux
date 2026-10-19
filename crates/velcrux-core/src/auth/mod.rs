//! Authentication and authorization.
//!
//! Per `SECURITY.md` §2 and §4, and `ARCHITECTURE.md` §2:
//!
//! - `Authenticator`: verifies the peer's identity from the TLS handshake.
//! - `Authorizer`: checks if an identity may perform an operation on a path.

use std::path::Path;

use crate::error::{ProtocolError, Result, VelcruxError};
use crate::storage::{VPath, VPathError};
use crate::transport::identity::Identity;

pub mod attestation;
pub use attestation::{
    generate_target_attestation, verify_target_attestation, AttestationEnvelope, AttestationError,
    AttestationKey, AttestationPayload, AttestationReport, AttestationStatus, AttestationVerifier,
    VerifiedAttestation, ATTESTATION_DOMAIN_SEPARATOR, ATTESTATION_VERSION_1, DEFAULT_SIG_EXT,
};

pub mod pubkey;
pub use pubkey::{
    compute_signed_payload, create_pubkey_auth_token, verify_pubkey_auth_token, AuthorizedKeys,
    AUTH_EXPORTER_LABEL, AUTH_SIGNATURE_PREFIX, EXPORTER_SECRET_LEN, SSH_PUBKEY_TOKEN_LEN,
};

/// Permissions bitset (wire-compatible u64).
///
/// Matches `SECURITY.md` §4: upload, download, list, delete, sync, resume, admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PermSet(u64);

impl PermSet {
    pub const UPLOAD: PermSet = PermSet(1 << 0);
    pub const DOWNLOAD: PermSet = PermSet(1 << 1);
    pub const LIST: PermSet = PermSet(1 << 2);
    pub const DELETE: PermSet = PermSet(1 << 3);
    pub const SYNC: PermSet = PermSet(1 << 4);
    pub const RESUME: PermSet = PermSet(1 << 5);
    pub const ADMIN: PermSet = PermSet(1 << 6);
    pub const SYNC_DELETE: PermSet = PermSet(1 << 7);

    /// All non-admin permissions.
    pub const ALL_TRANSFER: PermSet =
        PermSet(Self::UPLOAD.0 | Self::DOWNLOAD.0 | Self::LIST.0 | Self::SYNC.0 | Self::RESUME.0);

    /// Construct from wire u64.
    pub const fn from_wire(bits: u64) -> Self {
        Self(bits)
    }

    /// Encode to wire u64.
    pub const fn to_wire(self) -> u64 {
        self.0
    }

    /// Check if a permission is granted.
    pub fn has(self, perm: PermSet) -> bool {
        (self.0 & perm.0) != 0
    }

    /// Union of two permission sets.
    pub fn union(self, other: PermSet) -> PermSet {
        PermSet(self.0 | other.0)
    }
}

impl std::ops::BitOr for PermSet {
    type Output = PermSet;
    fn bitor(self, rhs: PermSet) -> PermSet {
        self.union(rhs)
    }
}

/// Predefined RBAC roles (`CLAUDE.md` §4 Open Question #1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full administrative authority (all permissions including admin, delete, and sync_delete).
    Admin,
    /// Standard operator with full transfer capabilities and single-file delete, but no bulk sync deletion.
    Operator,
    /// Automated sync writer capable of uploading, downloading, listing, and syncing (no deletion privileges).
    SyncWriter,
    /// Automated replication agent explicitly authorized to prune extraneous remote files during sync.
    SyncReplica,
    /// Read-only access for downloading and listing.
    ReadOnly,
}

impl Role {
    /// Get the permissions associated with this role.
    pub fn permissions(self) -> PermSet {
        match self {
            Role::Admin => {
                PermSet::ADMIN | PermSet::ALL_TRANSFER | PermSet::DELETE | PermSet::SYNC_DELETE
            }
            Role::Operator => PermSet::ALL_TRANSFER | PermSet::DELETE,
            Role::SyncWriter => {
                PermSet::UPLOAD
                    | PermSet::DOWNLOAD
                    | PermSet::LIST
                    | PermSet::SYNC
                    | PermSet::RESUME
            }
            Role::SyncReplica => {
                PermSet::UPLOAD
                    | PermSet::DOWNLOAD
                    | PermSet::LIST
                    | PermSet::SYNC
                    | PermSet::RESUME
                    | PermSet::SYNC_DELETE
            }
            Role::ReadOnly => PermSet::DOWNLOAD | PermSet::LIST,
        }
    }
}

impl std::str::FromStr for Role {
    type Err = VelcruxError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().replace('-', "_").as_str() {
            "admin" => Ok(Role::Admin),
            "operator" => Ok(Role::Operator),
            "sync_writer" => Ok(Role::SyncWriter),
            "sync_replica" => Ok(Role::SyncReplica),
            "read_only" | "readonly" => Ok(Role::ReadOnly),
            other => Err(VelcruxError::Config(format!(
                "unknown role {other:?}, expected: admin, operator, sync_writer, sync_replica, read_only"
            ))),
        }
    }
}

/// Operation being authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Upload,
    Download,
    List,
    Delete,
    Sync,
    Resume,
    Admin,
    SyncDelete,
}

impl Op {
    /// The permission bit required for this operation.
    pub fn required_perm(self) -> PermSet {
        match self {
            Op::Upload => PermSet::UPLOAD,
            Op::Download => PermSet::DOWNLOAD,
            Op::List => PermSet::LIST,
            Op::Delete => PermSet::DELETE,
            Op::Sync => PermSet::SYNC,
            Op::Resume => PermSet::RESUME,
            Op::Admin => PermSet::ADMIN,
            Op::SyncDelete => PermSet::SYNC_DELETE,
        }
    }
}

/// Server-side deletion policy governing remote deletions and `sync --delete` (`CLAUDE.md` §4 Open Question #1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeletionPolicy {
    /// Only identities possessing `PermSet::ADMIN` are allowed to delete remote files or execute `sync --delete`.
    /// This is the safe default, strictly answering Open Question #1 in the negative for unprivileged clients.
    AdminOnly,
    /// Deletions are permitted if the identity holds an explicit grant with `PermSet::DELETE` (for single files)
    /// or `PermSet::SYNC_DELETE` / `PermSet::ADMIN` (for directory sync deletions).
    ExplicitGrant,
    /// Remote deletions are globally forbidden across the entire server, regardless of grants or admin role.
    Disabled,
    /// Deletions are allowed (subject to permissions) but rate-limited to avoid catastrophic accidental bulk wipes.
    RateLimited {
        /// Maximum number of deletions permitted within the time window.
        max_deletions: u32,
        /// Sliding window duration in seconds.
        window_secs: u64,
    },
}

impl Default for DeletionPolicy {
    fn default() -> Self {
        DeletionPolicy::AdminOnly
    }
}

impl std::str::FromStr for DeletionPolicy {
    type Err = VelcruxError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().replace('_', "-").as_str() {
            "admin-only" | "admin" => Ok(DeletionPolicy::AdminOnly),
            "explicit-grant" | "explicit" => Ok(DeletionPolicy::ExplicitGrant),
            "disabled" | "deny" | "none" => Ok(DeletionPolicy::Disabled),
            "rate-limited" => Ok(DeletionPolicy::RateLimited {
                max_deletions: 60,
                window_secs: 60,
            }),
            other => Err(VelcruxError::Config(format!(
                "unknown deletion policy {other:?}, expected: admin-only, explicit-grant, disabled, rate-limited"
            ))),
        }
    }
}

/// Thread-safe sliding-window deletion rate limiter.
#[derive(Debug, Clone)]
pub struct DeletionLimiter {
    history: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, Vec<std::time::Instant>>>,
    >,
}

impl Default for DeletionLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl DeletionLimiter {
    pub fn new() -> Self {
        Self {
            history: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Check if identity is within rate limits and record the deletion if allowed.
    pub fn check_and_record(&self, identity: &str, max_deletions: u32, window_secs: u64) -> bool {
        let mut guard = match self.history.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(window_secs);

        let timestamps = guard.entry(identity.to_string()).or_default();
        timestamps.retain(|&t| now.duration_since(t) <= window);

        if timestamps.len() as u32 >= max_deletions {
            false
        } else {
            timestamps.push(now);
            true
        }
    }

    /// Reset history (useful in tests).
    pub fn reset(&self) {
        let mut guard = match self.history.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clear();
    }
}

/// A grant: identity + path prefix + permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The identity name this grant applies to.
    pub identity: String,
    /// The path prefix (directory) this grant covers. Must be a valid VPath prefix.
    pub path_prefix: String,
    /// Permissions granted for this prefix.
    pub permissions: PermSet,
}

/// Trait for authenticating a peer from the TLS handshake or via channel-bound token.
///
/// The `Connection` provides the peer's `Identity` (derived from the
/// certificate chain). The authenticator verifies it against its trust store
/// and returns a validated `Identity` or an error.
pub trait Authenticator: Send + Sync {
    /// Verify the peer identity. Returns the verified identity on success.
    fn authenticate(&self, identity: &Identity) -> Result<Identity>;

    /// Authenticate a peer using an opaque token and the connection's exporter secret.
    /// Default implementation fails closed.
    fn authenticate_token(
        &self,
        _mechanism: u16,
        _token: &[u8],
        _exporter_secret: &[u8; pubkey::EXPORTER_SECRET_LEN],
    ) -> Result<Identity> {
        Err(VelcruxError::Protocol(ProtocolError::InvalidIdentity(
            "token authentication not supported by this authenticator",
        )))
    }
}

/// Trait for authorizing an operation.
///
/// Given an identity, operation, and raw (root-relative) path, returns a
/// validated `VPath` on success or an error the caller must collapse to a
/// coarse "not found" on the wire (`PROTOCOL.md` §10). Authorization is
/// deny-by-default: an identity with no matching grant is denied.
pub trait Authorizer: Send + Sync {
    /// Check if `identity` may perform `op` on `raw_path`.
    ///
    /// `raw_path` is the untrusted, root-relative path taken from the wire.
    /// It is validated with [`VPath::validate`] *before* any grant lookup, so
    /// a malformed path is rejected regardless of grants. Returns the
    /// validated `VPath` only when a grant covers the path and carries the
    /// permission bit required by `op`.
    fn check(&self, identity: &Identity, op: Op, raw_path: &str) -> Result<VPath>;

    /// The union of all permissions granted to `identity` across every
    /// matching grant, regardless of path. Used to populate the `AUTH_OK`
    /// `permissions` field so the client learns its coarse capabilities up
    /// front. This is advisory: every individual operation is still checked
    /// against the specific path via [`check`](Self::check).
    fn granted_permissions(&self, identity: &Identity) -> PermSet;
}

/// A simple file-based authorizer for the MVP.
///
/// Reads grants from a TOML file with the structure defined in `SECURITY.md` §4.
pub struct FileAuthorizer {
    grants: Vec<Grant>,
}

impl FileAuthorizer {
    /// Create a new empty authorizer (for testing).
    pub fn new() -> Self {
        Self { grants: Vec::new() }
    }

    /// Load grants from a TOML file.
    ///
    /// Fails closed: an unknown permission string or a malformed grant path
    /// is a hard configuration error rather than being silently dropped,
    /// so a typo can never quietly widen or narrow access.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| VelcruxError::Config(format!("read auth file: {e}")))?;
        let cfg: AuthConfig = toml::from_str(&content)
            .map_err(|e| VelcruxError::Config(format!("parse auth file: {e}")))?;
        let mut grants = Vec::with_capacity(cfg.grant.len());
        for g in cfg.grant {
            grants.push(grant_from_toml(g)?);
        }
        Ok(Self { grants })
    }

    /// Construct directly from a list of grants (tests, in-process setup).
    pub fn from_grants(grants: Vec<Grant>) -> Self {
        Self { grants }
    }
}

impl Default for FileAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal TOML structure for grants.
#[derive(Debug, serde::Deserialize)]
struct AuthConfig {
    grant: Vec<GrantToml>,
}

#[derive(Debug, serde::Deserialize)]
struct GrantToml {
    identity: String,
    path: String,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    role: Option<String>,
}

/// Parse a single grant from its TOML form, failing closed on any
/// malformed field.
///
/// Permission strings are matched exactly; an unknown string is a hard
/// error (never silently ignored). The grant path is normalized from the
/// operator convention — a leading `/` means "relative to the storage
/// root" — into a canonical root-relative prefix: leading and trailing
/// slashes are stripped, and the resulting non-empty prefix is validated
/// with [`VPath::validate`]. The bare root grant (`/`, `""`, or `//`)
/// normalizes to `""`, which matches the whole root.
fn grant_from_toml(g: GrantToml) -> Result<Grant> {
    let mut perms = PermSet::default();
    if let Some(ref r) = g.role {
        let role: Role = std::str::FromStr::from_str(r)?;
        perms = perms.union(role.permissions());
    }
    for p in &g.permissions {
        let bit = match p.as_str() {
            "upload" => PermSet::UPLOAD,
            "download" => PermSet::DOWNLOAD,
            "list" => PermSet::LIST,
            "delete" => PermSet::DELETE,
            "sync" => PermSet::SYNC,
            "resume" => PermSet::RESUME,
            "admin" => PermSet::ADMIN,
            "sync_delete" | "sync-delete" => PermSet::SYNC_DELETE,
            other => {
                return Err(VelcruxError::Config(format!(
                    "unknown permission {other:?} for identity {:?}",
                    g.identity
                )));
            }
        };
        perms = perms.union(bit);
    }

    let prefix = normalize_grant_prefix(&g.path).map_err(|e| {
        VelcruxError::Config(format!(
            "invalid grant path {:?} for identity {:?}: {e}",
            g.path, g.identity
        ))
    })?;

    Ok(Grant {
        identity: g.identity,
        path_prefix: prefix,
        permissions: perms,
    })
}

/// Normalize an operator-supplied grant path into a canonical root-relative
/// prefix. Returns `Ok("")` for the whole-root grant. Non-root prefixes are
/// validated with [`VPath::validate`] so a grant can never name a path the
/// wire could not.
fn normalize_grant_prefix(raw: &str) -> std::result::Result<String, VPathError> {
    let trimmed = raw.trim_start_matches('/').trim_end_matches('/');
    if trimmed.is_empty() {
        // Whole-root grant ("/", "", "//").
        return Ok(String::new());
    }
    // Validate the normalized prefix exactly as a wire path would be.
    let vpath = VPath::validate(trimmed)?;
    Ok(vpath.as_str().to_string())
}

impl Authorizer for FileAuthorizer {
    fn check(&self, identity: &Identity, op: Op, raw_path: &str) -> Result<VPath> {
        let trimmed = raw_path.trim_start_matches('/').trim_end_matches('/');
        let (vpath, path) = if trimmed.is_empty() {
            if op == Op::Sync || op == Op::List {
                (VPath::root(), "")
            } else {
                return Err(VelcruxError::Protocol(ProtocolError::InvalidPath));
            }
        } else {
            let v = VPath::validate(trimmed)
                .map_err(|_| VelcruxError::Protocol(ProtocolError::InvalidPath))?;
            (v, trimmed)
        };

        // 2. Longest-matching-prefix grant for this identity. Matching is at
        //    component boundaries so `data/customerA` does NOT match
        //    `data/customerAB/...`. The whole-root grant ("") matches all.
        let mut best: Option<&Grant> = None;
        let mut best_len: Option<usize> = None;
        for grant in &self.grants {
            if grant.identity != identity.name {
                continue;
            }
            if let Some(plen) = prefix_match_len(&grant.path_prefix, path) {
                if best_len.map_or(true, |b| plen > b) {
                    best_len = Some(plen);
                    best = Some(grant);
                }
            }
        }

        // 3. No matching grant → deny. Deny-by-default (`SECURITY.md` §4).
        let grant = best.ok_or_else(|| VelcruxError::Protocol(ProtocolError::PermissionDenied))?;

        // 4. The matched grant must carry the permission this op requires.
        //    `admin` does NOT imply `delete` — each bit is explicit.
        let allowed = if op == Op::SyncDelete {
            grant.permissions.has(PermSet::SYNC_DELETE)
                || (grant.permissions.has(PermSet::ADMIN) && grant.permissions.has(PermSet::DELETE))
        } else {
            grant.permissions.has(op.required_perm())
        };
        if !allowed {
            return Err(VelcruxError::Protocol(ProtocolError::PermissionDenied));
        }

        // The validated path is already root-relative; return it unchanged.
        Ok(vpath)
    }

    fn granted_permissions(&self, identity: &Identity) -> PermSet {
        let mut perms = PermSet::default();
        for grant in &self.grants {
            if grant.identity == identity.name {
                perms = perms.union(grant.permissions);
            }
        }
        perms
    }
}

/// If `grant_prefix` covers `path`, return the number of matched bytes of
/// the (normalized) prefix so the caller can pick the longest match;
/// otherwise `None`.
///
/// `grant_prefix` is tolerant of the operator leading/trailing-slash
/// convention and is compared at component boundaries: a prefix matches
/// `path` only when `path` equals it exactly or continues with a `/`
/// immediately after it. The whole-root prefix (`""`) matches everything
/// with length 0, so any more specific grant wins over it.
fn prefix_match_len(grant_prefix: &str, path: &str) -> Option<usize> {
    let gp = grant_prefix.trim_start_matches('/').trim_end_matches('/');
    if gp.is_empty() {
        return Some(0); // whole-root grant
    }
    if path == gp {
        return Some(gp.len());
    }
    if path.len() > gp.len() && path.starts_with(gp) && path.as_bytes()[gp.len()] == b'/' {
        return Some(gp.len());
    }
    None
}

pub mod crl;
pub use crl::CrlStore;

/// The mTLS authenticator.
///
/// Validates identity extracted from mTLS handshake and checks revocation status
/// against the configured Certificate Revocation List (CRL) store.
#[derive(Debug, Clone, Default)]
pub struct MtlsAuthenticator {
    crl_store: Option<std::sync::Arc<CrlStore>>,
}

impl MtlsAuthenticator {
    pub fn new() -> Self {
        Self { crl_store: None }
    }

    pub fn with_crl_store(crl_store: std::sync::Arc<CrlStore>) -> Self {
        Self {
            crl_store: Some(crl_store),
        }
    }

    pub fn crl_store(&self) -> Option<&std::sync::Arc<CrlStore>> {
        self.crl_store.as_ref()
    }
}

impl Authenticator for MtlsAuthenticator {
    fn authenticate(&self, identity: &Identity) -> Result<Identity> {
        if let Some(ref crl) = self.crl_store {
            if !identity.serial_hex.is_empty() && crl.is_revoked(&identity.serial_hex) {
                return Err(VelcruxError::Protocol(ProtocolError::InvalidIdentity(
                    "certificate revoked in CRL",
                )));
            }
        }
        Ok(identity.clone())
    }
}

/// An authenticator that checks SSH-style Ed25519 public keys against an `AuthorizedKeys` set.
#[derive(Debug, Clone, Default)]
pub struct PubkeyAuthenticator {
    authorized_keys: AuthorizedKeys,
}

impl PubkeyAuthenticator {
    pub fn new(authorized_keys: AuthorizedKeys) -> Self {
        Self { authorized_keys }
    }
}

impl Authenticator for PubkeyAuthenticator {
    fn authenticate(&self, _identity: &Identity) -> Result<Identity> {
        Err(VelcruxError::Protocol(ProtocolError::InvalidIdentity(
            "mTLS certificate authentication not supported by PubkeyAuthenticator",
        )))
    }

    fn authenticate_token(
        &self,
        mechanism: u16,
        token: &[u8],
        exporter_secret: &[u8; pubkey::EXPORTER_SECRET_LEN],
    ) -> Result<Identity> {
        if mechanism != crate::protocol::message::AUTH_MECHANISM_SSH_PUBKEY {
            return Err(VelcruxError::Protocol(ProtocolError::InvalidIdentity(
                "unsupported mechanism for PubkeyAuthenticator",
            )));
        }
        self.authorized_keys.authenticate(token, exporter_secret)
    }
}

/// An authenticator that supports both mTLS certificates and SSH-style Ed25519 public keys.
#[derive(Debug, Clone, Default)]
pub struct HybridAuthenticator {
    mtls: MtlsAuthenticator,
    authorized_keys: Option<AuthorizedKeys>,
}

impl HybridAuthenticator {
    pub fn new(authorized_keys: Option<AuthorizedKeys>) -> Self {
        Self {
            mtls: MtlsAuthenticator::new(),
            authorized_keys,
        }
    }

    pub fn with_crl(
        authorized_keys: Option<AuthorizedKeys>,
        crl_store: Option<std::sync::Arc<CrlStore>>,
    ) -> Self {
        let mtls = match crl_store {
            Some(store) => MtlsAuthenticator::with_crl_store(store),
            None => MtlsAuthenticator::new(),
        };
        Self {
            mtls,
            authorized_keys,
        }
    }
}

impl Authenticator for HybridAuthenticator {
    fn authenticate(&self, identity: &Identity) -> Result<Identity> {
        self.mtls.authenticate(identity)
    }

    fn authenticate_token(
        &self,
        mechanism: u16,
        token: &[u8],
        exporter_secret: &[u8; pubkey::EXPORTER_SECRET_LEN],
    ) -> Result<Identity> {
        if mechanism == crate::protocol::message::AUTH_MECHANISM_SSH_PUBKEY {
            if let Some(ref ak) = self.authorized_keys {
                return ak.authenticate(token, exporter_secret);
            }
        }
        Err(VelcruxError::Protocol(ProtocolError::InvalidIdentity(
            "unsupported token authentication mechanism or no authorized_keys configured",
        )))
    }
}

#[cfg(test)]
mod tests;
