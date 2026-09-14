//! Authentication and authorization.
//!
//! Per `SECURITY.md` §2 and §4, and `ARCHITECTURE.md` §2:
//!
//! - `Authenticator`: verifies the peer's identity from the TLS handshake.
//! - `Authorizer`: checks if an identity may perform an operation on a path.

use std::path::Path;

use crate::error::{Result, VelcruxError, ProtocolError};
use crate::storage::{VPath, VPathError};
use crate::transport::identity::Identity;

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

    /// All non-admin permissions.
    pub const ALL_TRANSFER: PermSet = PermSet(
        Self::UPLOAD.0 | Self::DOWNLOAD.0 | Self::LIST.0 | Self::SYNC.0 | Self::RESUME.0,
    );

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
        }
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

/// Trait for authenticating a peer from the TLS handshake.
///
/// The `Connection` provides the peer's `Identity` (derived from the
/// certificate chain). The authenticator verifies it against its trust store
/// and returns a validated `Identity` or an error.
pub trait Authenticator: Send + Sync {
    /// Verify the peer identity. Returns the verified identity on success.
    fn authenticate(&self, identity: &Identity) -> Result<Identity>;
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
    for p in &g.permissions {
        let bit = match p.as_str() {
            "upload" => PermSet::UPLOAD,
            "download" => PermSet::DOWNLOAD,
            "list" => PermSet::LIST,
            "delete" => PermSet::DELETE,
            "sync" => PermSet::SYNC,
            "resume" => PermSet::RESUME,
            "admin" => PermSet::ADMIN,
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
        // 1. Validate the untrusted wire path FIRST, before any grant lookup.
        //    A malformed path is rejected regardless of grants. Traversal,
        //    absolute paths, control chars, and over-long components are all
        //    caught here (`storage::VPath::validate`).
        let vpath = VPath::validate(raw_path)
            .map_err(|_| VelcruxError::Protocol(ProtocolError::InvalidPath))?;
        let path = vpath.as_str();

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
        let grant =
            best.ok_or_else(|| VelcruxError::Protocol(ProtocolError::PermissionDenied))?;

        // 4. The matched grant must carry the permission this op requires.
        //    `admin` does NOT imply `delete` — each bit is explicit.
        if !grant.permissions.has(op.required_perm()) {
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

/// The mTLS authenticator for the MVP.
///
/// Verifies that the peer's certificate chain is trusted by the configured
/// CA roots. The identity is already extracted by the transport layer;
/// we just need to ensure the chain was validated by rustls.
pub struct MtlsAuthenticator {
    // In the MVP, the TLS handshake already validates the chain.
    // This struct exists for the trait shape and future extensibility.
}

impl MtlsAuthenticator {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for MtlsAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for MtlsAuthenticator {
    fn authenticate(&self, identity: &Identity) -> Result<Identity> {
        // The TLS handshake (via rustls) already validated the chain.
        // We trust the identity extracted from the verified certificate.
        Ok(identity.clone())
    }
}

#[cfg(test)]
mod tests;