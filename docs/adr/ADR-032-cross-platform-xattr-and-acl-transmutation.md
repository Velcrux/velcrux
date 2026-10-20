# ADR-032: Cross-Platform POSIX Extended Attribute (xattr) & NFSv4 ACL Transmutation Engine (`CLAUDE.md` §4 Open Question #2)

Status: Accepted · Date: 2026-10-20

## Context

A fundamental impedance mismatch exists between operating systems regarding extended attributes (xattrs) and access control lists (ACLs):
1. **Linux Kernel Namespace Requirements**:
   - Linux filesystems (ext4, XFS, Btrfs, F2FS) partition attributes into four explicit kernel namespaces: `user.*`, `trusted.*`, `security.*`, and `system.*`.
   - Normal unprivileged user space processes may only manipulate `user.*` attributes (e.g. `user.mime_type`).
   - If an application attempts to write an un-namespaced attribute (e.g. `mime_type` or `com.apple.quarantine`), the Linux VFS immediately returns `EOPNOTSUPP` ("Operation not supported").
   - ACLs on Linux are maintained as POSIX 1003.1e draft binary data structures in `system.posix_acl_access` (and `system.posix_acl_default` for directories).
2. **Apple macOS (Darwin) Conventions**:
   - macOS does **not** employ a mandatory `user.` namespace prefix.
   - Applications and system daemons utilize reverse-DNS attribute identifiers (e.g. `com.apple.quarantine`, `com.apple.metadata:kMDItemFinderComment`, `com.apple.TextEncoding`) or bare attribute names (e.g. `mime_type`).
   - Writing an attribute named `user.mime_type` on macOS results in a literal attribute of that name, which native macOS utilities and Spotlight will not recognize.
   - ACLs on macOS follow the NFSv4 rich Access Control Entry (ACE) specification (`com.apple.acl.text`), supporting explicit `allow`/`deny` actions and fine-grained permissions (`read`, `write`, `execute`, `append`, `delete`, `readattr`, `writeattr`, `readextattr`, `writeextattr`, `readsecurity`, `writesecurity`, `chown`).
3. **Fidelity Dilemma (`CLAUDE.md` §4 Open Question #2)**:
   - "Extended attribute / ACL fidelity: how much do we promise on Linux vs macOS?"
   - Naively transferring attributes without conversion leads to `EOPNOTSUPP` errors on Linux or unusable metadata on macOS.
   - Discarding all attributes breaks backup and synchronisation fidelity.
   - Transmutation must be bidirectional, lossless for common attributes, configurable via explicit policies, and strictly safe against privilege escalation (`SECURITY.md` §4).

## Options Considered

1. **Option 1: Raw Untranslated Preservation (Strict / Fail-Fast)**:
   - Preserve exact byte-for-byte attribute names and binary payloads as provided by the source.
   - *Rejected*: Syncing from macOS to Linux ext4 fails with `EOPNOTSUPP` on every file bearing standard macOS metadata; syncing from Linux to macOS creates alien `user.` prefixes that native Mac apps ignore.
2. **Option 2: Always Use Hidden Metadata Sidecars (`.velcrux-xattr`)**:
   - Never write native kernel attributes; store all metadata exclusively in sidecar files.
   - *Rejected*: Inefficient for local apps relying on native filesystem attributes (Spotlight, Finder tags, Linux extended attributes, system tools); creates file clutter unless requested by the user.
3. **Option 3: First-Class Bidirectional Transmutation Engine with Configurable Policies (`ADR-032`)**:
   - Create a dedicated `XattrTransmuter` and intermediate canonical ACL representation (`CanonicalAcl` / `CanonicalAce`).
   - Dynamically map Linux `user.*` prefixes to native macOS attributes, and macOS reverse-DNS / bare attributes to Linux `user.*` namespaces.
   - Convert between Linux POSIX 1003.1e draft ACLs (`system.posix_acl_access`) and macOS Darwin NFSv4 ACEs (`com.apple.acl.text`).
   - Provide configurable fidelity policies: `Transmute` (default), `Strict`, `Sidecar`, and `Strip`.
   - Enforce fail-closed security boundary checks (`PermSet::ADMIN`) for privileged namespaces (`security.*`, `trusted.*`, `system.*`).

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Platform Discriminator & Policies (`crates/velcrux-core/src/storage/xattr.rs`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformOs {
    Linux,
    MacOS,
    Windows,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum XattrPolicy {
    #[default]
    Transmute,
    Strict,
    Sidecar,
    Strip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum AclPolicy {
    #[default]
    Transmute,
    Strict,
    Sidecar,
    Strip,
}
```

- **`Transmute`** (default):
  - **Linux -> macOS**: Strips the leading `user.` prefix so attributes manifest as native macOS attributes (e.g. `user.mime_type` -> `mime_type`, `user.com.apple.quarantine` -> `com.apple.quarantine`).
  - **macOS -> Linux**: Prepends `user.` to un-namespaced or reverse-DNS attributes (e.g. `com.apple.quarantine` -> `user.com.apple.quarantine`, `mime_type` -> `user.mime_type`) to comply with ext4/XFS kernel rules.
  - **Round-Trip Fidelity**: Round-tripping between Linux and macOS produces the original attribute names losslessly.
- **`Strict`**: Preserves raw attribute names without modification; fails or rejects if target OS rejects namespace.
- **`Sidecar`**: Persists attributes directly into `.<filename>.velcrux-xattr` metadata sidecars without touching target filesystem xattr APIs.
- **`Strip`**: Completely discards extended attributes and ACLs.

### 2. Canonical ACL Intermediate Representation (`CanonicalAcl`)

- Bridges Linux POSIX 1003.1e draft ACLs and macOS Darwin NFSv4 ACEs:
  - `AcePrincipal`: `Owner`, `GroupOwner`, `NamedUser(u32, Option<String>)`, `NamedGroup(u32, Option<String>)`, `Mask`, `Other`, `Everyone`.
  - `AceType`: `Allow`, `Deny`.
  - `AcePermissions`: POSIX mode triple (`read`, `write`, `execute`) and NFSv4 fine-grained permission flags (`append`, `delete`, `readattr`, `writeattr`, `readextattr`, `writeextattr`, `readsecurity`, `writesecurity`, `chown`).
  - `AceFlags`: `default_entry`, `file_inherit`, `directory_inherit`, `inherited`.
- Provides parsers and emitters:
  - `from_posix_acl_binary` & `to_posix_acl_binary`: Decodes and encodes raw Linux kernel `system.posix_acl_access` binary headers and 8-byte `struct acl_ea_entry` records.
  - `from_posix_acl_text` & `to_posix_acl_text`: Parses and renders `getfacl`/`setfacl` human-readable syntax.
  - `from_darwin_acl_text` & `to_darwin_acl_text`: Parses and renders macOS Darwin NFSv4 syntax (`com.apple.acl.text` / `ls -le` / `chmod +a`).

### 3. Security Boundary Enforcement (`SECURITY.md` §4)

- Extended attributes in privileged namespaces (`security.*`, `trusted.*`, `system.*`) can alter system security posture (e.g. SELinux labels, Linux file capabilities `security.capability`, filesystem internals).
- The transmuter checks client permissions against `PermSet::ADMIN`.
- Non-admin clients attempting to set or transmute privileged attributes have them filtered out or rejected fail-closed with `ErrorCode::InvalidPath`.

### 4. Reconciliation Diff Integration (`crates/velcrux-core/src/sync/directory.rs`)

- Directory diff reconciliation (`plan_directory_diff_with_options` / `plan_directory_sync`) compares source and destination attributes using `xattrs_are_compatible`.
- If `xattr_policy` is `Transmute`, source attributes transmuted to target conventions are evaluated against destination attributes; if they match, files are marked `FileActionType::Unchanged`, eliminating unnecessary transfers.

### 5. Telemetry & Metrics (`crates/velcrux-server/src/metrics.rs`)

Exposes Prometheus counters:
```text
# HELP velcrux_xattr_transmutations_total Total cross-platform extended attribute and ACL transmutations
# TYPE velcrux_xattr_transmutations_total counter
velcrux_xattr_transmutations_total{direction="all"} 42
velcrux_xattr_transmutations_total{direction="linux_to_macos"} 28
velcrux_xattr_transmutations_total{direction="macos_to_linux"} 14
```

### 6. CLI Flags (`velcrux sync`)

```bash
velcrux sync /src /dst --xattr-policy transmute --acl-policy transmute
velcrux sync /src /dst --xattr-policy strip
velcrux sync /src /dst --xattr-policy sidecar
```

## Consequences

- Resolves `CLAUDE.md` §4 Open Question #2 completely.
- Zero unsafe code (`#![forbid(unsafe_code)]`).
- Full cross-platform compatibility between Linux and macOS.
