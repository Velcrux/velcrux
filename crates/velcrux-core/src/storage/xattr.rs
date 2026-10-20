//! Cross-platform POSIX Extended Attribute (xattr) & NFSv4 ACL Transmutation Engine.
//!
//! Resolves `CLAUDE.md` §4 Open Question #2 ("Extended attribute / ACL fidelity:
//! how much do we promise on Linux vs macOS?") via ADR-032.
//!
//! # Problem
//! - **Linux**: Extended attributes require an explicit namespace prefix (`user.*`,
//!   `security.*`, `trusted.*`, `system.*`). Ext4/XFS/Btrfs return `EOPNOTSUPP` if
//!   an attribute lacks a valid namespace prefix. ACLs are represented as POSIX 1003.1e
//!   draft binary structures in `system.posix_acl_access` / `system.posix_acl_default`.
//! - **macOS (Darwin)**: Extended attributes do not use a mandatory `user.` prefix,
//!   and typically use reverse-DNS names (e.g. `com.apple.quarantine`,
//!   `com.apple.metadata:kMDItemFinderComment`) or plain names (e.g. `mime_type`).
//!   ACLs follow NFSv4 rich ACE syntax (stored in `com.apple.acl.text` or manipulated
//!   via Darwin `chmod +a` / `ls -le`).
//!
//! # Solution
//! This engine provides:
//! 1. `PlatformOs`: Target platform discriminator (`Linux`, `MacOS`, `Windows`, `Unknown`).
//! 2. `XattrPolicy` & `AclPolicy`: Configurable fidelity modes (`Transmute`, `Strict`, `Sidecar`, `Strip`).
//! 3. `CanonicalAcl` & `CanonicalAce`: Intermediate representation bridging POSIX 1003.1e draft ACLs
//!    and Darwin NFSv4 ACEs with lossless round-tripping for common permission matrices.
//! 4. `XattrTransmuter`: Bidirectional mapper converting attribute names and ACL payloads
//!    across operating systems while strictly respecting `SECURITY.md` §4 privilege boundaries.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, VelcruxError};

// POSIX 1003.1e binary representation constants (Linux uapi/linux/posix_acl_xattr.h)
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;

const ACL_READ: u16 = 0x04;
const ACL_WRITE: u16 = 0x02;
const ACL_EXECUTE: u16 = 0x01;
const ACL_UNDEFINED_ID: u32 = 0xFFFF_FFFF;

/// Operating system platform discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformOs {
    /// Linux (kernel namespace prefixes required: `user.*`, `system.*`, `security.*`).
    Linux,
    /// Apple macOS Darwin (reverse-DNS, un-prefixed user attributes, NFSv4 ACLs).
    MacOS,
    /// Microsoft Windows (NTFS alternate data streams / DACLs).
    Windows,
    /// Unknown or generic target platform.
    Unknown,
}

impl PlatformOs {
    /// Detect the current runtime operating system.
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            PlatformOs::Linux
        }
        #[cfg(target_os = "macos")]
        {
            PlatformOs::MacOS
        }
        #[cfg(target_os = "windows")]
        {
            PlatformOs::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            PlatformOs::Unknown
        }
    }
}

impl fmt::Display for PlatformOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformOs::Linux => write!(f, "linux"),
            PlatformOs::MacOS => write!(f, "macos"),
            PlatformOs::Windows => write!(f, "windows"),
            PlatformOs::Unknown => write!(f, "unknown"),
        }
    }
}

impl FromStr for PlatformOs {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "linux" => Ok(PlatformOs::Linux),
            "macos" | "darwin" | "osx" => Ok(PlatformOs::MacOS),
            "windows" | "win" => Ok(PlatformOs::Windows),
            "unknown" | "generic" => Ok(PlatformOs::Unknown),
            other => Err(VelcruxError::Config(format!(
                "invalid platform os '{other}'; expected linux, macos, windows, or unknown"
            ))),
        }
    }
}

/// Extended attribute preservation and transmutation policy (`ADR-032`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum XattrPolicy {
    /// Automatically translate attribute names and namespaces to match target OS conventions (default).
    /// - Linux -> macOS: Strips `user.` prefix (`user.mime_type` -> `mime_type`, `user.com.apple.*` -> `com.apple.*`).
    /// - macOS -> Linux: Prepends `user.` to un-namespaced or `com.apple.*` attributes to satisfy kernel rules.
    #[default]
    Transmute,
    /// Strict preservation: Retains raw attribute names without modification.
    Strict,
    /// Sidecar fallback: Writes extended attributes to `.<filename>.velcrux-xattr` metadata sidecars.
    Sidecar,
    /// Discards all extended attributes during transfer.
    Strip,
}

impl fmt::Display for XattrPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XattrPolicy::Transmute => write!(f, "transmute"),
            XattrPolicy::Strict => write!(f, "strict"),
            XattrPolicy::Sidecar => write!(f, "sidecar"),
            XattrPolicy::Strip => write!(f, "strip"),
        }
    }
}

impl FromStr for XattrPolicy {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "transmute" => Ok(XattrPolicy::Transmute),
            "strict" => Ok(XattrPolicy::Strict),
            "sidecar" => Ok(XattrPolicy::Sidecar),
            "strip" | "ignore" | "none" => Ok(XattrPolicy::Strip),
            other => Err(VelcruxError::Config(format!(
                "invalid xattr policy '{other}'; expected transmute, strict, sidecar, or strip"
            ))),
        }
    }
}

/// Access Control List (ACL) fidelity policy (`ADR-032`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AclPolicy {
    /// Transmute between Linux POSIX 1003.1e draft ACLs and macOS Darwin NFSv4 ACEs (default).
    #[default]
    Transmute,
    /// Strict mode: only apply ACLs if target natively supports the identical representation.
    Strict,
    /// Store ACL representations in metadata sidecars.
    Sidecar,
    /// Strip all ACLs, preserving only standard POSIX mode bits (e.g. 0o755 / 0o644).
    Strip,
}

impl fmt::Display for AclPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclPolicy::Transmute => write!(f, "transmute"),
            AclPolicy::Strict => write!(f, "strict"),
            AclPolicy::Sidecar => write!(f, "sidecar"),
            AclPolicy::Strip => write!(f, "strip"),
        }
    }
}

impl FromStr for AclPolicy {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "transmute" => Ok(AclPolicy::Transmute),
            "strict" => Ok(AclPolicy::Strict),
            "sidecar" => Ok(AclPolicy::Sidecar),
            "strip" | "ignore" | "none" => Ok(AclPolicy::Strip),
            other => Err(VelcruxError::Config(format!(
                "invalid acl policy '{other}'; expected transmute, strict, sidecar, or strip"
            ))),
        }
    }
}

/// ACE Principal (user, group, mask, other, or everyone).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcePrincipal {
    /// Owner object (`user::` in POSIX, `owner@` in NFSv4).
    Owner,
    /// Owning group object (`group::` in POSIX, `group@` in NFSv4).
    GroupOwner,
    /// Named user by UID and optional username.
    NamedUser(u32, Option<String>),
    /// Named group by GID and optional groupname.
    NamedGroup(u32, Option<String>),
    /// POSIX ACL mask entry (`mask::`).
    Mask,
    /// POSIX other/world entry (`other::`).
    Other,
    /// Darwin / NFSv4 everyone principal.
    Everyone,
}

impl AcePrincipal {
    /// Display name or identifier.
    pub fn id_string(&self) -> String {
        match self {
            AcePrincipal::Owner => "owner".to_string(),
            AcePrincipal::GroupOwner => "group_owner".to_string(),
            AcePrincipal::NamedUser(uid, name) => name.clone().unwrap_or_else(|| uid.to_string()),
            AcePrincipal::NamedGroup(gid, name) => name.clone().unwrap_or_else(|| gid.to_string()),
            AcePrincipal::Mask => "mask".to_string(),
            AcePrincipal::Other => "other".to_string(),
            AcePrincipal::Everyone => "everyone".to_string(),
        }
    }
}

/// ACE access type (Allow or Deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AceType {
    Allow,
    Deny,
}

/// Fine-grained ACE permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
pub struct AcePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub append: bool,
    pub delete: bool,
    pub read_attr: bool,
    pub write_attr: bool,
    pub read_xattr: bool,
    pub write_xattr: bool,
    pub read_security: bool,
    pub write_security: bool,
    pub chown: bool,
}

impl AcePermissions {
    /// Construct permissions from standard POSIX read/write/execute bits.
    pub fn from_posix_mode(r: bool, w: bool, x: bool) -> Self {
        Self {
            read: r,
            write: w,
            execute: x,
            append: w,
            delete: w,
            read_attr: r,
            write_attr: w,
            read_xattr: r,
            write_xattr: w,
            read_security: r,
            write_security: w,
            chown: false,
        }
    }

    /// Convert back to POSIX `(read, write, execute)` triple.
    pub fn to_posix_mode(&self) -> (bool, bool, bool) {
        (
            self.read || self.read_attr || self.read_xattr,
            self.write || self.append || self.delete || self.write_attr || self.write_xattr,
            self.execute,
        )
    }

    /// Parse POSIX mode string (e.g. `rwx`, `r-x`, `r--`, `---`).
    pub fn from_posix_str(s: &str) -> Result<Self, VelcruxError> {
        let s = s.trim();
        if s.len() != 3 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "posix acl permission must be 3 characters (e.g. rwx, r-x)",
            )));
        }
        let bytes = s.as_bytes();
        let r = bytes[0] == b'r';
        let w = bytes[1] == b'w';
        let x = bytes[2] == b'x';
        Ok(Self::from_posix_mode(r, w, x))
    }

    /// Render standard POSIX 3-character permission string (`rwx`, `r-x`, etc.).
    pub fn to_posix_str(&self) -> String {
        let (r, w, x) = self.to_posix_mode();
        format!(
            "{}{}{}",
            if r { 'r' } else { '-' },
            if w { 'w' } else { '-' },
            if x { 'x' } else { '-' }
        )
    }

    /// Parse Darwin NFSv4 comma-separated permission names.
    pub fn from_darwin_str(s: &str) -> Self {
        let mut perms = Self::default();
        for part in s.split(',') {
            match part.trim().to_ascii_lowercase().as_str() {
                "read" | "read_data" | "list_directory" => perms.read = true,
                "write" | "write_data" | "add_file" => perms.write = true,
                "execute" | "execute_file" | "search_directory" => perms.execute = true,
                "append" | "append_data" | "add_subdirectory" => perms.append = true,
                "delete" | "delete_child" => perms.delete = true,
                "readattr" | "read_attributes" => perms.read_attr = true,
                "writeattr" | "write_attributes" => perms.write_attr = true,
                "readextattr" | "read_xattr" => perms.read_xattr = true,
                "writeextattr" | "write_xattr" => perms.write_xattr = true,
                "readsecurity" | "read_acl" => perms.read_security = true,
                "writesecurity" | "write_acl" => perms.write_security = true,
                "chown" | "change_owner" => perms.chown = true,
                _ => {}
            }
        }
        perms
    }

    /// Render Darwin NFSv4 comma-separated permission list.
    pub fn to_darwin_str(&self) -> String {
        let mut list = Vec::new();
        if self.read {
            list.push("read");
        }
        if self.write {
            list.push("write");
        }
        if self.execute {
            list.push("execute");
        }
        if self.append && !self.write {
            list.push("append");
        }
        if self.delete {
            list.push("delete");
        }
        if self.read_attr {
            list.push("readattr");
        }
        if self.write_attr {
            list.push("writeattr");
        }
        if self.read_xattr {
            list.push("readextattr");
        }
        if self.write_xattr {
            list.push("writeextattr");
        }
        if self.read_security {
            list.push("readsecurity");
        }
        if self.write_security {
            list.push("writesecurity");
        }
        if self.chown {
            list.push("chown");
        }
        if list.is_empty() {
            "read".to_string()
        } else {
            list.join(",")
        }
    }
}

/// Inheritance and entry flags for ACE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
pub struct AceFlags {
    /// True if this entry represents a directory POSIX default ACL (`default:` prefix).
    pub default_entry: bool,
    /// Darwin/NFSv4 file_inherit.
    pub file_inherit: bool,
    /// Darwin/NFSv4 directory_inherit.
    pub directory_inherit: bool,
    /// Darwin/NFSv4 inherited.
    pub inherited: bool,
}

/// Single Canonical Access Control Entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAce {
    pub principal: AcePrincipal,
    pub ace_type: AceType,
    pub permissions: AcePermissions,
    pub flags: AceFlags,
}

/// Canonical intermediate representation of an Access Control List.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CanonicalAcl {
    pub entries: Vec<CanonicalAce>,
}

impl CanonicalAcl {
    /// Create an empty Canonical ACL.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// True if ACL contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add an ACE entry.
    pub fn add_entry(&mut self, ace: CanonicalAce) {
        self.entries.push(ace);
    }

    /// Parse POSIX 1003.1e ACL text representation (output of `getfacl`).
    pub fn from_posix_acl_text(text: &str, is_default: bool) -> Result<Self, VelcruxError> {
        let mut acl = Self::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (is_def, line_content) = if let Some(stripped) = line.strip_prefix("default:") {
                (true, stripped)
            } else {
                (is_default, line)
            };

            let parts: Vec<&str> = line_content.split(':').collect();
            if parts.len() < 3 {
                continue;
            }

            let tag = parts[0].trim();
            let qual = parts[1].trim();
            let perm_str = parts[2].trim();

            let perms = AcePermissions::from_posix_str(perm_str)?;
            let flags = AceFlags {
                default_entry: is_def,
                file_inherit: is_def,
                directory_inherit: is_def,
                inherited: false,
            };

            let principal = match tag {
                "user" | "u" => {
                    if qual.is_empty() {
                        AcePrincipal::Owner
                    } else if let Ok(uid) = qual.parse::<u32>() {
                        AcePrincipal::NamedUser(uid, None)
                    } else {
                        AcePrincipal::NamedUser(0, Some(qual.to_string()))
                    }
                }
                "group" | "g" => {
                    if qual.is_empty() {
                        AcePrincipal::GroupOwner
                    } else if let Ok(gid) = qual.parse::<u32>() {
                        AcePrincipal::NamedGroup(gid, None)
                    } else {
                        AcePrincipal::NamedGroup(0, Some(qual.to_string()))
                    }
                }
                "mask" | "m" => AcePrincipal::Mask,
                "other" | "o" => AcePrincipal::Other,
                _ => continue,
            };

            acl.add_entry(CanonicalAce {
                principal,
                ace_type: AceType::Allow,
                permissions: perms,
                flags,
            });
        }
        Ok(acl)
    }

    /// Render to POSIX 1003.1e textual format (`getfacl`/`setfacl` compatible).
    pub fn to_posix_acl_text(&self, only_default: bool) -> String {
        let mut out = String::new();
        for ace in &self.entries {
            if ace.flags.default_entry != only_default {
                continue;
            }
            let prefix = if only_default { "default:" } else { "" };
            let perm = ace.permissions.to_posix_str();
            match &ace.principal {
                AcePrincipal::Owner => out.push_str(&format!("{prefix}user::{perm}\n")),
                AcePrincipal::GroupOwner => out.push_str(&format!("{prefix}group::{perm}\n")),
                AcePrincipal::NamedUser(uid, name) => {
                    let id = name.clone().unwrap_or_else(|| uid.to_string());
                    out.push_str(&format!("{prefix}user:{id}:{perm}\n"));
                }
                AcePrincipal::NamedGroup(gid, name) => {
                    let id = name.clone().unwrap_or_else(|| gid.to_string());
                    out.push_str(&format!("{prefix}group:{id}:{perm}\n"));
                }
                AcePrincipal::Mask => out.push_str(&format!("{prefix}mask::{perm}\n")),
                AcePrincipal::Other | AcePrincipal::Everyone => {
                    out.push_str(&format!("{prefix}other::{perm}\n"))
                }
            }
        }
        out
    }

    /// Parse Darwin / macOS NFSv4 ACL text representation (from `com.apple.acl.text` or `ls -le`).
    /// Format: `user:uid:allow:perms` or `group:gid:allow:perms:flags`.
    pub fn from_darwin_acl_text(text: &str) -> Result<Self, VelcruxError> {
        let mut acl = Self::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 4 {
                continue;
            }

            let tag = parts[0].trim().to_ascii_lowercase();
            let qual = parts[1].trim();
            let act = parts[2].trim().to_ascii_lowercase();
            let perm_str = parts[3].trim();
            let flags_str = if parts.len() > 4 { parts[4].trim() } else { "" };

            let ace_type = match act.as_str() {
                "deny" => AceType::Deny,
                _ => AceType::Allow,
            };

            let principal = match tag.as_str() {
                "user" => {
                    if let Ok(uid) = qual.parse::<u32>() {
                        AcePrincipal::NamedUser(uid, None)
                    } else if qual == "owner" {
                        AcePrincipal::Owner
                    } else {
                        AcePrincipal::NamedUser(0, Some(qual.to_string()))
                    }
                }
                "group" => {
                    if let Ok(gid) = qual.parse::<u32>() {
                        AcePrincipal::NamedGroup(gid, None)
                    } else if qual == "group_owner" {
                        AcePrincipal::GroupOwner
                    } else {
                        AcePrincipal::NamedGroup(0, Some(qual.to_string()))
                    }
                }
                "everyone" => AcePrincipal::Everyone,
                "mask" => AcePrincipal::Mask,
                _ => AcePrincipal::Other,
            };

            let permissions = AcePermissions::from_darwin_str(perm_str);
            let flags = AceFlags {
                default_entry: flags_str.contains("directory_inherit"),
                file_inherit: flags_str.contains("file_inherit"),
                directory_inherit: flags_str.contains("directory_inherit"),
                inherited: flags_str.contains("inherited"),
            };

            acl.add_entry(CanonicalAce {
                principal,
                ace_type,
                permissions,
                flags,
            });
        }
        Ok(acl)
    }

    /// Render to Darwin / macOS NFSv4 ACL text (`com.apple.acl.text`).
    pub fn to_darwin_acl_text(&self) -> String {
        let mut out = String::new();
        for ace in &self.entries {
            let (tag, qual) = match &ace.principal {
                AcePrincipal::Owner => ("user", "owner".to_string()),
                AcePrincipal::GroupOwner => ("group", "group_owner".to_string()),
                AcePrincipal::NamedUser(uid, name) => {
                    ("user", name.clone().unwrap_or_else(|| uid.to_string()))
                }
                AcePrincipal::NamedGroup(gid, name) => {
                    ("group", name.clone().unwrap_or_else(|| gid.to_string()))
                }
                AcePrincipal::Mask => ("mask", "mask".to_string()),
                AcePrincipal::Other => ("user", "other".to_string()),
                AcePrincipal::Everyone => ("everyone", "".to_string()),
            };

            let act = match ace.ace_type {
                AceType::Allow => "allow",
                AceType::Deny => "deny",
            };

            let perm = ace.permissions.to_darwin_str();
            let mut flags = Vec::new();
            if ace.flags.file_inherit {
                flags.push("file_inherit");
            }
            if ace.flags.directory_inherit {
                flags.push("directory_inherit");
            }
            if ace.flags.inherited {
                flags.push("inherited");
            }

            if flags.is_empty() {
                out.push_str(&format!("{tag}:{qual}:{act}:{perm}\n"));
            } else {
                out.push_str(&format!("{tag}:{qual}:{act}:{perm}:{}\n", flags.join(",")));
            }
        }
        out
    }

    /// Parse Linux POSIX 1003.1e binary representation (from `system.posix_acl_access`).
    pub fn from_posix_acl_binary(bytes: &[u8], is_default: bool) -> Result<Self, VelcruxError> {
        if bytes.len() < 4 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "truncated posix acl binary header",
            )));
        }
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if version != POSIX_ACL_XATTR_VERSION {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unsupported posix acl binary version",
            )));
        }

        let mut acl = Self::new();
        let mut offset = 4;
        while offset + 8 <= bytes.len() {
            let tag = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            let perm = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]);
            let id = u32::from_le_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            offset += 8;

            let r = (perm & ACL_READ) != 0;
            let w = (perm & ACL_WRITE) != 0;
            let x = (perm & ACL_EXECUTE) != 0;
            let perms = AcePermissions::from_posix_mode(r, w, x);

            let principal = match tag {
                ACL_USER_OBJ => AcePrincipal::Owner,
                ACL_USER => AcePrincipal::NamedUser(id, None),
                ACL_GROUP_OBJ => AcePrincipal::GroupOwner,
                ACL_GROUP => AcePrincipal::NamedGroup(id, None),
                ACL_MASK => AcePrincipal::Mask,
                ACL_OTHER => AcePrincipal::Other,
                _ => continue,
            };

            acl.add_entry(CanonicalAce {
                principal,
                ace_type: AceType::Allow,
                permissions: perms,
                flags: AceFlags {
                    default_entry: is_default,
                    file_inherit: is_default,
                    directory_inherit: is_default,
                    inherited: false,
                },
            });
        }
        Ok(acl)
    }

    /// Serialize to Linux POSIX 1003.1e binary representation (`system.posix_acl_access`).
    pub fn to_posix_acl_binary(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.entries.len() * 8);
        out.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());

        for ace in &self.entries {
            let (tag, id) = match &ace.principal {
                AcePrincipal::Owner => (ACL_USER_OBJ, ACL_UNDEFINED_ID),
                AcePrincipal::NamedUser(uid, _) => (ACL_USER, *uid),
                AcePrincipal::GroupOwner => (ACL_GROUP_OBJ, ACL_UNDEFINED_ID),
                AcePrincipal::NamedGroup(gid, _) => (ACL_GROUP, *gid),
                AcePrincipal::Mask => (ACL_MASK, ACL_UNDEFINED_ID),
                AcePrincipal::Other | AcePrincipal::Everyone => (ACL_OTHER, ACL_UNDEFINED_ID),
            };

            let (r, w, x) = ace.permissions.to_posix_mode();
            let mut perm: u16 = 0;
            if r {
                perm |= ACL_READ;
            }
            if w {
                perm |= ACL_WRITE;
            }
            if x {
                perm |= ACL_EXECUTE;
            }

            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&perm.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }
}

/// Bidirectional cross-platform extended attribute and ACL transmutation engine.
#[derive(Debug, Clone)]
pub struct XattrTransmuter {
    source_os: PlatformOs,
    target_os: PlatformOs,
    xattr_policy: XattrPolicy,
    acl_policy: AclPolicy,
    is_admin: bool,
}

impl XattrTransmuter {
    /// Construct a new transmuter between source and target OS platforms.
    pub fn new(source_os: PlatformOs, target_os: PlatformOs) -> Self {
        Self {
            source_os,
            target_os,
            xattr_policy: XattrPolicy::Transmute,
            acl_policy: AclPolicy::Transmute,
            is_admin: false,
        }
    }

    /// Configure the extended attribute policy.
    pub fn with_xattr_policy(mut self, policy: XattrPolicy) -> Self {
        self.xattr_policy = policy;
        self
    }

    /// Configure the ACL policy.
    pub fn with_acl_policy(mut self, policy: AclPolicy) -> Self {
        self.acl_policy = policy;
        self
    }

    /// Configure client administrative privilege status (`SECURITY.md` §4).
    pub fn with_admin(mut self, is_admin: bool) -> Self {
        self.is_admin = is_admin;
        self
    }

    /// Return the telemetry label describing the transmutation direction.
    pub fn direction_label(&self) -> &'static str {
        match (self.source_os, self.target_os) {
            (PlatformOs::Linux, PlatformOs::MacOS) => "linux_to_macos",
            (PlatformOs::MacOS, PlatformOs::Linux) => "macos_to_linux",
            (s, t) if s == t => "same_os",
            _ => "generic",
        }
    }

    /// Returns true if the attribute is in a privileged namespace (`SECURITY.md` §4).
    pub fn is_privileged(name: &str) -> bool {
        name.starts_with("security.") || name.starts_with("trusted.") || name.starts_with("system.")
    }

    /// Transmute a single attribute name based on source/target OS rules.
    /// Returns `None` if the attribute should be stripped or filtered out by policy/security.
    pub fn transmute_name(&self, name: &str) -> Option<String> {
        if self.xattr_policy == XattrPolicy::Strip {
            return None;
        }

        // Strict mode retains raw names, subject only to admin gate
        if self.xattr_policy == XattrPolicy::Strict {
            if !self.is_admin && Self::is_privileged(name) {
                return None;
            }
            return Some(name.to_string());
        }

        if self.source_os == self.target_os && self.source_os != PlatformOs::Unknown {
            if !self.is_admin && Self::is_privileged(name) {
                return None;
            }
            return Some(name.to_string());
        }

        // Transmute policy: bidirectional namespace bridging
        match (self.source_os, self.target_os) {
            (_, PlatformOs::MacOS) => {
                // Target is macOS
                if name == "system.posix_acl_access" || name == "system.posix_acl_default" {
                    if self.acl_policy == AclPolicy::Strip {
                        return None;
                    }
                    return Some("com.apple.acl.text".to_string());
                }
                if let Some(unprefixed) = name.strip_prefix("user.") {
                    // Strip "user." so attributes manifest natively on macOS
                    Some(unprefixed.to_string())
                } else if Self::is_privileged(name) {
                    if self.is_admin {
                        Some(name.to_string())
                    } else {
                        None
                    }
                } else {
                    Some(name.to_string())
                }
            }
            (_, PlatformOs::Linux) => {
                // Target is Linux
                if name == "com.apple.acl.text" {
                    if self.acl_policy == AclPolicy::Strip {
                        return None;
                    }
                    if self.is_admin {
                        return Some("system.posix_acl_access".to_string());
                    } else {
                        return Some("user.posix_acl_access".to_string());
                    }
                }
                if name.starts_with("user.") {
                    Some(name.to_string())
                } else if Self::is_privileged(name) {
                    if self.is_admin {
                        Some(name.to_string())
                    } else {
                        None
                    }
                } else {
                    // Linux ext4/xfs requires user.* namespace for non-privileged attributes
                    Some(format!("user.{name}"))
                }
            }
            _ => {
                // Same OS or other OS
                if !self.is_admin && Self::is_privileged(name) {
                    None
                } else {
                    Some(name.to_string())
                }
            }
        }
    }

    /// Transmute a single extended attribute entry `(name, value)` pair.
    pub fn transmute_entry(&self, name: &str, value: &[u8]) -> Option<(String, Vec<u8>)> {
        if self.xattr_policy == XattrPolicy::Strip {
            return None;
        }

        // Security boundary check
        if !self.is_admin && Self::is_privileged(name) {
            return None;
        }

        // Check for ACL transmutation
        if (name == "system.posix_acl_access" || name == "system.posix_acl_default")
            && self.target_os == PlatformOs::MacOS
        {
            if self.acl_policy == AclPolicy::Strip {
                return None;
            }
            if self.acl_policy == AclPolicy::Transmute {
                // Try decoding binary POSIX ACL first, then fallback to text
                let is_default = name.ends_with("default");
                let acl = CanonicalAcl::from_posix_acl_binary(value, is_default)
                    .or_else(|_| {
                        std::str::from_utf8(value)
                            .map_err(|_| {
                                VelcruxError::Protocol(ProtocolError::Malformed("not utf8"))
                            })
                            .and_then(|s| CanonicalAcl::from_posix_acl_text(s, is_default))
                    })
                    .unwrap_or_default();

                let darwin_text = acl.to_darwin_acl_text();
                return Some(("com.apple.acl.text".to_string(), darwin_text.into_bytes()));
            }
        } else if name == "com.apple.acl.text" && self.target_os == PlatformOs::Linux {
            if self.acl_policy == AclPolicy::Strip {
                return None;
            }
            if self.acl_policy == AclPolicy::Transmute {
                if let Ok(text) = std::str::from_utf8(value) {
                    if let Ok(acl) = CanonicalAcl::from_darwin_acl_text(text) {
                        let target_name = if self.is_admin {
                            "system.posix_acl_access"
                        } else {
                            "user.posix_acl_access"
                        };
                        return Some((target_name.to_string(), acl.to_posix_acl_binary()));
                    }
                }
            }
        }

        // General attribute name transmutation
        let new_name = self.transmute_name(name)?;
        Some((new_name, value.to_vec()))
    }

    /// Transmute an entire list of extended attributes.
    pub fn transmute_entries(&self, entries: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::with_capacity(entries.len());
        for (name, val) in entries {
            if let Some(transmuted) = self.transmute_entry(name, val) {
                out.push(transmuted);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_os_parsing() {
        assert_eq!(PlatformOs::from_str("linux").unwrap(), PlatformOs::Linux);
        assert_eq!(PlatformOs::from_str("macos").unwrap(), PlatformOs::MacOS);
        assert_eq!(PlatformOs::from_str("darwin").unwrap(), PlatformOs::MacOS);
        assert_eq!(
            PlatformOs::from_str("windows").unwrap(),
            PlatformOs::Windows
        );
        assert_eq!(
            PlatformOs::from_str("unknown").unwrap(),
            PlatformOs::Unknown
        );
        assert!(PlatformOs::from_str("solaris").is_err());
    }

    #[test]
    fn test_xattr_policy_parsing() {
        assert_eq!(
            XattrPolicy::from_str("transmute").unwrap(),
            XattrPolicy::Transmute
        );
        assert_eq!(
            XattrPolicy::from_str("strict").unwrap(),
            XattrPolicy::Strict
        );
        assert_eq!(
            XattrPolicy::from_str("sidecar").unwrap(),
            XattrPolicy::Sidecar
        );
        assert_eq!(XattrPolicy::from_str("strip").unwrap(), XattrPolicy::Strip);
    }

    #[test]
    fn test_acl_policy_parsing() {
        assert_eq!(
            AclPolicy::from_str("transmute").unwrap(),
            AclPolicy::Transmute
        );
        assert_eq!(AclPolicy::from_str("strict").unwrap(), AclPolicy::Strict);
        assert_eq!(AclPolicy::from_str("strip").unwrap(), AclPolicy::Strip);
    }

    #[test]
    fn test_posix_to_darwin_attribute_transmutation() {
        let transmuter = XattrTransmuter::new(PlatformOs::Linux, PlatformOs::MacOS);

        // Linux user namespace attributes strip user.
        assert_eq!(
            transmuter.transmute_name("user.mime_type"),
            Some("mime_type".to_string())
        );
        assert_eq!(
            transmuter.transmute_name("user.com.apple.quarantine"),
            Some("com.apple.quarantine".to_string())
        );
        assert_eq!(
            transmuter.transmute_name("user.com.apple.metadata:kMDItemFinderComment"),
            Some("com.apple.metadata:kMDItemFinderComment".to_string())
        );

        // Unprivileged client cannot transmute security namespaces
        assert_eq!(transmuter.transmute_name("security.selinux"), None);
        assert_eq!(transmuter.transmute_name("trusted.overlay"), None);

        // Admin can preserve security namespaces
        let admin_transmuter = transmuter.clone().with_admin(true);
        assert_eq!(
            admin_transmuter.transmute_name("security.selinux"),
            Some("security.selinux".to_string())
        );
    }

    #[test]
    fn test_darwin_to_posix_attribute_transmutation() {
        let transmuter = XattrTransmuter::new(PlatformOs::MacOS, PlatformOs::Linux);

        // macOS reverse-DNS attributes gain user. namespace on Linux
        assert_eq!(
            transmuter.transmute_name("com.apple.quarantine"),
            Some("user.com.apple.quarantine".to_string())
        );
        assert_eq!(
            transmuter.transmute_name("com.apple.metadata:kMDItemFinderComment"),
            Some("user.com.apple.metadata:kMDItemFinderComment".to_string())
        );
        assert_eq!(
            transmuter.transmute_name("mime_type"),
            Some("user.mime_type".to_string())
        );

        // Already namespaced attributes are preserved
        assert_eq!(
            transmuter.transmute_name("user.custom_tag"),
            Some("user.custom_tag".to_string())
        );
    }

    #[test]
    fn test_lossless_roundtrip_transmutation() {
        let mac_to_linux = XattrTransmuter::new(PlatformOs::MacOS, PlatformOs::Linux);
        let linux_to_mac = XattrTransmuter::new(PlatformOs::Linux, PlatformOs::MacOS);

        let orig_darwin = "com.apple.quarantine";
        let on_linux = mac_to_linux.transmute_name(orig_darwin).unwrap();
        assert_eq!(on_linux, "user.com.apple.quarantine");

        let back_on_darwin = linux_to_mac.transmute_name(&on_linux).unwrap();
        assert_eq!(back_on_darwin, orig_darwin);

        let orig_linux = "user.author_meta";
        let on_darwin = linux_to_mac.transmute_name(orig_linux).unwrap();
        assert_eq!(on_darwin, "author_meta");

        let back_on_linux = mac_to_linux.transmute_name(&on_darwin).unwrap();
        assert_eq!(back_on_linux, orig_linux);
    }

    #[test]
    fn test_posix_binary_acl_to_darwin_transmutation() {
        // Construct canonical Linux POSIX ACL:
        // user::rwx, user:1000:r-x, group::r-x, mask::r-x, other::r--
        let mut acl = CanonicalAcl::new();
        acl.add_entry(CanonicalAce {
            principal: AcePrincipal::Owner,
            ace_type: AceType::Allow,
            permissions: AcePermissions::from_posix_mode(true, true, true),
            flags: AceFlags::default(),
        });
        acl.add_entry(CanonicalAce {
            principal: AcePrincipal::NamedUser(1000, None),
            ace_type: AceType::Allow,
            permissions: AcePermissions::from_posix_mode(true, false, true),
            flags: AceFlags::default(),
        });
        acl.add_entry(CanonicalAce {
            principal: AcePrincipal::GroupOwner,
            ace_type: AceType::Allow,
            permissions: AcePermissions::from_posix_mode(true, false, true),
            flags: AceFlags::default(),
        });
        acl.add_entry(CanonicalAce {
            principal: AcePrincipal::Mask,
            ace_type: AceType::Allow,
            permissions: AcePermissions::from_posix_mode(true, false, true),
            flags: AceFlags::default(),
        });
        acl.add_entry(CanonicalAce {
            principal: AcePrincipal::Other,
            ace_type: AceType::Allow,
            permissions: AcePermissions::from_posix_mode(true, false, false),
            flags: AceFlags::default(),
        });

        let binary_posix = acl.to_posix_acl_binary();
        assert_eq!(binary_posix.len(), 4 + 5 * 8); // header (4) + 5 entries (40) = 44 bytes

        // Transmute to Darwin
        let transmuter =
            XattrTransmuter::new(PlatformOs::Linux, PlatformOs::MacOS).with_admin(true);

        let (darwin_name, darwin_bytes) = transmuter
            .transmute_entry("system.posix_acl_access", &binary_posix)
            .expect("must transmute ACL");

        assert_eq!(darwin_name, "com.apple.acl.text");
        let darwin_text = String::from_utf8(darwin_bytes).expect("darwin acl utf8");
        assert!(darwin_text.contains("user:owner:allow:read,write,execute"));
        assert!(darwin_text.contains("user:1000:allow:read,execute"));
        assert!(darwin_text.contains("group:group_owner:allow:read,execute"));
        assert!(darwin_text.contains("user:other:allow:read"));
    }

    #[test]
    fn test_darwin_acl_text_to_linux_posix_transmutation() {
        let darwin_acl_text = "user:1000:allow:read,execute\ngroup:1001:allow:read\n";

        let transmuter =
            XattrTransmuter::new(PlatformOs::MacOS, PlatformOs::Linux).with_admin(true);

        let (posix_name, posix_bytes) = transmuter
            .transmute_entry("com.apple.acl.text", darwin_acl_text.as_bytes())
            .expect("must transmute ACL");

        assert_eq!(posix_name, "system.posix_acl_access");

        // Decode binary POSIX ACL back into canonical representation
        let decoded = CanonicalAcl::from_posix_acl_binary(&posix_bytes, false).unwrap();
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(
            decoded.entries[0].principal,
            AcePrincipal::NamedUser(1000, None)
        );
        assert_eq!(
            decoded.entries[0].permissions.to_posix_mode(),
            (true, false, true)
        );
        assert_eq!(
            decoded.entries[1].principal,
            AcePrincipal::NamedGroup(1001, None)
        );
        assert_eq!(
            decoded.entries[1].permissions.to_posix_mode(),
            (true, false, false)
        );
    }

    #[test]
    fn test_policy_strip_discards_all() {
        let transmuter = XattrTransmuter::new(PlatformOs::Linux, PlatformOs::MacOS)
            .with_xattr_policy(XattrPolicy::Strip)
            .with_acl_policy(AclPolicy::Strip);

        let entries = vec![
            ("user.mime_type".to_string(), b"text/plain".to_vec()),
            ("system.posix_acl_access".to_string(), vec![1, 2, 3]),
        ];

        let result = transmuter.transmute_entries(&entries);
        assert!(result.is_empty());
    }
}
