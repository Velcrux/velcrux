//! Transfer planning, dry-run evaluation, pattern filtering, and safe deletion semantics.
//!
//! Implements `docs/REQUIREMENTS.md` §57 ("Transfer Plan"), §58 ("Dry Run"), §59 ("Delete Semantics"),
//! §60 ("Security of Synchronization"), and §61 ("Transactional Synchronization").

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sync::directory::{DirectoryPlan, FileAction, FileActionType};

/// Explicit deletion mode for directory synchronization (`REQUIREMENTS.md` §59).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteMode {
    /// Safe default: never delete destination files, even if absent on source.
    None,
    /// Delete extraneous destination files before transfer starts to reclaim disk headroom.
    DeleteBefore,
    /// Delete extraneous destination files only after all transfers and commits have succeeded.
    DeleteAfter,
    /// Delete extraneous destination files AND any destination files matching exclude filter patterns.
    DeleteExcluded,
}

impl Default for DeleteMode {
    fn default() -> Self {
        DeleteMode::None
    }
}

impl fmt::Display for DeleteMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteMode::None => write!(f, "none"),
            DeleteMode::DeleteBefore => write!(f, "delete-before"),
            DeleteMode::DeleteAfter => write!(f, "delete-after"),
            DeleteMode::DeleteExcluded => write!(f, "delete-excluded"),
        }
    }
}

impl FromStr for DeleteMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "off" | "false" => Ok(DeleteMode::None),
            "delete-before" | "before" => Ok(DeleteMode::DeleteBefore),
            "delete-after" | "after" | "delete" => Ok(DeleteMode::DeleteAfter),
            "delete-excluded" | "excluded" => Ok(DeleteMode::DeleteExcluded),
            other => Err(format!(
                "invalid delete mode '{other}'; valid options: none, delete-before, delete-after, delete-excluded"
            )),
        }
    }
}

/// Errors raised when deletion safety guardrails are violated (`REQUIREMENTS.md` §59, §60).
#[derive(Debug, Error, Clone, PartialEq, Serialize, Deserialize)]
pub enum DeleteSafetyError {
    /// Attempted deletions exceed configured absolute file threshold.
    #[error("Deletion guardrail triggered: {attempted} files scheduled for deletion exceeds safety threshold of {limit} files (pass --force-delete to override)")]
    MaxFilesExceeded { attempted: usize, limit: usize },

    /// Attempted deletions exceed configured percentage threshold.
    #[error("Deletion guardrail triggered: {attempted_pct:.1}% of destination files scheduled for deletion exceeds safety threshold of {limit_pct:.1}% (pass --force-delete to override)")]
    MaxPercentageExceeded { attempted_pct: f64, limit_pct: f64 },

    /// Security violation: deletion path attempts to escape the destination root boundary.
    #[error(
        "Security violation: deletion path '{path}' attempts to escape destination root boundary"
    )]
    PathEscapeAttempt { path: String },

    /// Attempted deletion of a forbidden or protected path (e.g. root or system metadata).
    #[error("Security violation: deletion of protected path '{path}' is forbidden")]
    ProtectedPath { path: String },

    /// Destination directory path is empty or invalid.
    #[error("Invalid destination path: destination directory path is empty or root")]
    InvalidDestinationRoot,
}

/// Guardrails protecting against catastrophic or unintended deletions (`REQUIREMENTS.md` §59, §60).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeleteGuardrails {
    /// Maximum number of files permitted to be deleted in a single sync execution.
    pub max_delete_files: Option<usize>,
    /// Maximum percentage of total destination files permitted to be deleted (0.0 to 100.0).
    pub max_delete_pct: Option<f64>,
    /// If true, bypasses threshold limits (explicit operator override).
    pub force_delete: bool,
}

impl Default for DeleteGuardrails {
    fn default() -> Self {
        Self {
            max_delete_files: None,
            max_delete_pct: None,
            force_delete: false,
        }
    }
}

impl DeleteGuardrails {
    /// Create new permissive guardrails with no thresholds unless explicitly set.
    pub fn permissive() -> Self {
        Self {
            max_delete_files: None,
            max_delete_pct: None,
            force_delete: false,
        }
    }

    /// Set maximum allowed deletion count.
    pub fn with_max_delete_files(mut self, max: Option<usize>) -> Self {
        self.max_delete_files = max;
        self
    }

    /// Set maximum allowed deletion percentage.
    pub fn with_max_delete_pct(mut self, pct: Option<f64>) -> Self {
        self.max_delete_pct = pct;
        self
    }

    /// Set whether force delete is enabled.
    pub fn with_force_delete(mut self, force: bool) -> Self {
        self.force_delete = force;
        self
    }

    /// Validate planned deletions against configured thresholds.
    pub fn validate_deletions(
        &self,
        total_dst_files: usize,
        delete_count: usize,
    ) -> Result<(), DeleteSafetyError> {
        if self.force_delete || delete_count == 0 {
            return Ok(());
        }

        if let Some(limit) = self.max_delete_files {
            if delete_count > limit {
                return Err(DeleteSafetyError::MaxFilesExceeded {
                    attempted: delete_count,
                    limit,
                });
            }
        }

        if let Some(limit_pct) = self.max_delete_pct {
            if total_dst_files > 0 {
                let pct = (delete_count as f64 / total_dst_files as f64) * 100.0;
                if pct > limit_pct {
                    return Err(DeleteSafetyError::MaxPercentageExceeded {
                        attempted_pct: pct,
                        limit_pct,
                    });
                }
            }
        }

        Ok(())
    }

    /// Sanitize and validate that a relative deletion path stays strictly within the target root.
    pub fn validate_deletion_path(
        rel_path: &str,
        dst_root: &Path,
    ) -> Result<PathBuf, DeleteSafetyError> {
        let clean = rel_path.trim().replace('\\', "/");
        if clean.is_empty() || clean == "." || clean == ".." || clean.starts_with('/') {
            return Err(DeleteSafetyError::PathEscapeAttempt {
                path: rel_path.to_string(),
            });
        }

        // Check for protected Velcrux directories
        if clean.starts_with(".velcrux-staging")
            || clean.starts_with(".velcrux-chunks")
            || clean.starts_with(".git")
        {
            return Err(DeleteSafetyError::ProtectedPath {
                path: rel_path.to_string(),
            });
        }

        // Verify lexical containment
        let rel = Path::new(&clean);
        for comp in rel.components() {
            match comp {
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(DeleteSafetyError::PathEscapeAttempt {
                        path: rel_path.to_string(),
                    });
                }
                Component::Normal(_) | Component::CurDir => {}
            }
        }

        let full_path = dst_root.join(rel);
        Ok(full_path)
    }
}

/// Glob-style path filter for inclusion and exclusion rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathFilter {
    /// Glob patterns to exclude.
    pub exclude_patterns: Vec<String>,
    /// Glob patterns to include (overrides exclude if matched).
    pub include_patterns: Vec<String>,
}

impl PathFilter {
    /// Create a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an exclusion pattern.
    pub fn add_exclude(&mut self, pattern: impl Into<String>) {
        self.exclude_patterns.push(pattern.into());
    }

    /// Add an inclusion pattern.
    pub fn add_include(&mut self, pattern: impl Into<String>) {
        self.include_patterns.push(pattern.into());
    }

    /// Determine if a relative file path is excluded by active rules.
    pub fn is_excluded(&self, rel_path: &str) -> bool {
        let norm_path = rel_path.replace('\\', "/");

        // If include patterns match, it is NOT excluded
        for inc in &self.include_patterns {
            if matches_glob(inc, &norm_path) {
                return false;
            }
        }

        // Check exclude patterns
        for exc in &self.exclude_patterns {
            if matches_glob(exc, &norm_path) {
                return true;
            }
        }

        false
    }
}

/// Pure-Rust glob matcher supporting `*`, `**`, `?`, and directory prefixes.
pub fn matches_glob(pattern: &str, path: &str) -> bool {
    let p_norm = pattern.trim().replace('\\', "/");
    let t_norm = path.trim().replace('\\', "/");

    if p_norm == "*" || p_norm == "**" {
        return true;
    }
    if p_norm == t_norm {
        return true;
    }

    // Direct extension match: e.g. "*.tmp"
    if p_norm.starts_with("*.") && !p_norm[2..].contains('/') && !p_norm[2..].contains('*') {
        let ext = &p_norm[1..]; // ".tmp"
        return t_norm.ends_with(ext);
    }

    // Directory wildcard match: e.g. "dir/*" or "dir/**"
    if let Some(prefix) = p_norm.strip_suffix("/**") {
        let prefix = prefix.trim_end_matches('/');
        return t_norm == prefix || t_norm.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = p_norm.strip_suffix("/*") {
        let prefix = prefix.trim_end_matches('/');
        if let Some(rest) = t_norm.strip_prefix(&format!("{prefix}/")) {
            return !rest.contains('/');
        }
        return false;
    }

    // Leading directory prefix match: e.g. "build/"
    if let Some(prefix) = p_norm.strip_suffix('/') {
        if t_norm == prefix || t_norm.starts_with(&format!("{prefix}/")) {
            return true;
        }
    }

    // Prefix wildcard match: e.g. "test_*"
    if let Some(prefix) = p_norm.strip_suffix('*') {
        if !prefix.contains('*') && !prefix.contains('?') {
            let filename = t_norm.rsplit('/').next().unwrap_or(&t_norm);
            return filename.starts_with(prefix) || t_norm.starts_with(prefix);
        }
    }

    // Suffix wildcard match: e.g. "*_test.rs"
    if let Some(suffix) = p_norm.strip_prefix('*') {
        if !suffix.contains('*') && !suffix.contains('?') {
            let filename = t_norm.rsplit('/').next().unwrap_or(&t_norm);
            return filename.ends_with(suffix);
        }
    }

    // Substring match: e.g. "*vendor*"
    if p_norm.starts_with('*') && p_norm.ends_with('*') && p_norm.len() > 2 {
        let sub = &p_norm[1..p_norm.len() - 1];
        if !sub.contains('*') && !sub.contains('?') {
            return t_norm.contains(sub);
        }
    }

    // Filename basename match: if pattern has no slashes, match on file basename
    if !p_norm.contains('/') {
        let filename = t_norm.rsplit('/').next().unwrap_or(&t_norm);
        if filename == p_norm {
            return true;
        }
    }

    // Recursive component-based wildcard matching
    glob_recursive_match(p_norm.as_bytes(), t_norm.as_bytes())
}

fn glob_recursive_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_p_idx = None;
    let mut star_t_idx = None;

    while t_idx < text.len() {
        if p_idx < pattern.len() && (pattern[p_idx] == b'?' || pattern[p_idx] == text[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < pattern.len() && pattern[p_idx] == b'*' {
            // Handle double star '**'
            if p_idx + 1 < pattern.len() && pattern[p_idx + 1] == b'*' {
                p_idx += 2;
                if p_idx < pattern.len() && pattern[p_idx] == b'/' {
                    p_idx += 1;
                }
            } else {
                p_idx += 1;
            }
            star_p_idx = Some(p_idx);
            star_t_idx = Some(t_idx);
        } else if let (Some(sp), Some(st)) = (star_p_idx, star_t_idx) {
            p_idx = sp;
            t_idx = st + 1;
            star_t_idx = Some(t_idx);
        } else {
            return false;
        }
    }

    while p_idx < pattern.len() && pattern[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == pattern.len()
}

/// Comprehensive Transfer Plan and reconciliation summary (`REQUIREMENTS.md` §57, §58).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferPlan {
    /// Source directory or URL.
    pub source_path: String,
    /// Destination directory or URL.
    pub destination_path: String,
    /// Total files identified in source tree.
    pub total_files: usize,
    /// Number of files identical on source and destination.
    pub files_unchanged: usize,
    /// Number of files existing on both sides with differing contents.
    pub files_modified: usize,
    /// Number of new files present on source but absent on destination.
    pub files_added: usize,
    /// Number of extraneous files present on destination but absent on source.
    pub files_deleted: usize,
    /// Number of files skipped due to exclude filters.
    pub files_excluded: usize,
    /// Total source dataset size in bytes.
    pub total_source_bytes: u64,
    /// Total data required to transfer over the wire in bytes.
    pub bytes_to_transfer: u64,
    /// Total data reusable from destination or chunk store in bytes.
    pub bytes_reusable: u64,
    /// Estimated bandwidth savings reduction percentage (0.0 to 100.0).
    pub estimated_reduction_pct: f64,
    /// Configured deletion mode.
    pub delete_mode: DeleteMode,
    /// Configured safety guardrails.
    pub guardrails: DeleteGuardrails,
    /// List of per-file planned actions.
    pub actions: Vec<FileAction>,
    /// Whether this plan was evaluated in dry-run mode.
    pub dry_run: bool,
}

impl TransferPlan {
    /// Construct a [`TransferPlan`] from an evaluated [`DirectoryPlan`] and configuration.
    pub fn from_directory_plan(
        src_path: &Path,
        dst_path: &Path,
        plan: &DirectoryPlan,
        delete_mode: DeleteMode,
        guardrails: DeleteGuardrails,
        files_excluded: usize,
        dry_run: bool,
    ) -> Self {
        let total_files =
            plan.summary.files_unchanged + plan.summary.files_modified + plan.summary.files_added;

        let total_source_bytes = plan
            .actions
            .iter()
            .filter(|a| a.action != FileActionType::Delete)
            .map(|a| a.src_size)
            .sum();

        Self {
            source_path: src_path.to_string_lossy().to_string(),
            destination_path: dst_path.to_string_lossy().to_string(),
            total_files,
            files_unchanged: plan.summary.files_unchanged,
            files_modified: plan.summary.files_modified,
            files_added: plan.summary.files_added,
            files_deleted: plan.summary.files_deleted,
            files_excluded,
            total_source_bytes,
            bytes_to_transfer: plan.summary.data_to_transfer,
            bytes_reusable: plan.summary.data_present,
            estimated_reduction_pct: plan.summary.estimated_reduction,
            delete_mode,
            guardrails,
            actions: plan.actions.clone(),
            dry_run,
        }
    }

    /// Formats the plan into an aligned report matching `REQUIREMENTS.md` §57 & §58.
    pub fn format_display(&self) -> String {
        let mode_desc = match self.delete_mode {
            DeleteMode::None => "None (safe default, preserves destination)",
            DeleteMode::DeleteBefore => "DeleteBefore (pre-transfer disk space reclamation)",
            DeleteMode::DeleteAfter => "DeleteAfter (post-commit verified deletion)",
            DeleteMode::DeleteExcluded => "DeleteExcluded (extraneous & filtered paths)",
        };

        let mut out = String::new();
        out.push_str("========================================================================================\n");
        if self.dry_run {
            out.push_str("                   VELCRUX TRANSFER PLAN (DRY-RUN EXECUTION PREVIEW)                   \n");
        } else {
            out.push_str("                      VELCRUX TRANSFER PLAN & RECONCILIATION                            \n");
        }
        out.push_str("========================================================================================\n");
        out.push_str(&format!("Source Directory     : {}\n", self.source_path));
        out.push_str(&format!(
            "Destination Directory: {}\n",
            self.destination_path
        ));
        out.push_str(&format!("Deletion Policy      : {}\n", mode_desc));
        out.push_str("----------------------------------------------------------------------------------------\n");
        out.push_str(&format!(
            "Files total:           {:>14}\n",
            format_count(self.total_files)
        ));
        out.push_str(&format!(
            "Files unchanged:       {:>14}\n",
            format_count(self.files_unchanged)
        ));
        out.push_str(&format!(
            "Files modified:        {:>14}\n",
            format_count(self.files_modified)
        ));
        out.push_str(&format!(
            "Files added:           {:>14}\n",
            format_count(self.files_added)
        ));
        out.push_str(&format!(
            "Files deleted:         {:>14}\n",
            format_count(self.files_deleted)
        ));
        if self.files_excluded > 0 {
            out.push_str(&format!(
                "Files excluded:        {:>14}\n",
                format_count(self.files_excluded)
            ));
        }
        out.push_str("----------------------------------------------------------------------------------------\n");
        out.push_str(&format!(
            "Total source data:     {:>14}\n",
            format_bytes(self.total_source_bytes)
        ));
        out.push_str(&format!(
            "Data already present:  {:>14}\n",
            format_bytes(self.bytes_reusable)
        ));
        out.push_str(&format!(
            "Data to transfer:      {:>14}\n",
            format_bytes(self.bytes_to_transfer)
        ));
        out.push_str(&format!(
            "Estimated reduction:   {:>13.1}%\n",
            self.estimated_reduction_pct
        ));
        out.push_str("========================================================================================\n");

        if self.dry_run {
            out.push_str("NOTE: Running in dry-run mode. Destination data was NOT modified.\n");
        }
        out
    }

    /// Convert plan into machine-readable JSON structure (`REQUIREMENTS.md` §36).
    pub fn to_json_value(&self) -> serde_json::Value {
        let action_items: Vec<_> = self
            .actions
            .iter()
            .map(|a| {
                serde_json::json!({
                    "action": match a.action {
                        FileActionType::Unchanged => "unchanged",
                        FileActionType::Modify => "modify",
                        FileActionType::Add => "add",
                        FileActionType::Delete => "delete",
                    },
                    "path": a.rel_path,
                    "src_size": a.src_size,
                    "dst_size": a.dst_size,
                    "bytes_to_transfer": a.bytes_to_transfer,
                    "bytes_reusable": a.bytes_reusable,
                })
            })
            .collect();

        serde_json::json!({
            "version": 1,
            "event": "transfer_plan",
            "dry_run": self.dry_run,
            "source": self.source_path,
            "destination": self.destination_path,
            "delete_mode": self.delete_mode.to_string(),
            "summary": {
                "total_files": self.total_files,
                "files_unchanged": self.files_unchanged,
                "files_modified": self.files_modified,
                "files_added": self.files_added,
                "files_deleted": self.files_deleted,
                "files_excluded": self.files_excluded,
                "total_source_bytes": self.total_source_bytes,
                "bytes_already_present": self.bytes_reusable,
                "bytes_to_transfer": self.bytes_to_transfer,
                "estimated_reduction_pct": self.estimated_reduction_pct,
            },
            "guardrails": {
                "max_delete_files": self.guardrails.max_delete_files,
                "max_delete_pct": self.guardrails.max_delete_pct,
                "force_delete": self.guardrails.force_delete,
            },
            "actions": action_items,
        })
    }

    /// Calculate estimated transfer duration in seconds for a given line rate in bytes/sec.
    pub fn estimated_duration_secs(&self, link_speed_bytes_sec: u64) -> f64 {
        if link_speed_bytes_sec == 0 {
            0.0
        } else {
            self.bytes_to_transfer as f64 / link_speed_bytes_sec as f64
        }
    }

    /// Validate that planned deletions satisfy configured guardrails.
    pub fn validate_safety(&self, total_dst_files: usize) -> Result<(), DeleteSafetyError> {
        if self.delete_mode == DeleteMode::None {
            return Ok(());
        }
        self.guardrails
            .validate_deletions(total_dst_files, self.files_deleted)
    }
}

fn format_count(count: usize) -> String {
    let s = count.to_string();
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    out
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.2} TB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_matching() {
        assert!(matches_glob("*.txt", "hello.txt"));
        assert!(matches_glob("*.txt", "sub/dir/hello.txt"));
        assert!(!matches_glob("*.txt", "hello.png"));

        assert!(matches_glob("dir/*", "dir/file.txt"));
        assert!(!matches_glob("dir/*", "dir/sub/file.txt"));
        assert!(matches_glob("dir/**", "dir/sub/nested/file.txt"));

        assert!(matches_glob("build/", "build/output.bin"));
        assert!(matches_glob("*.tmp", "cache.tmp"));
        assert!(matches_glob("prefix_*", "prefix_data.csv"));
        assert!(matches_glob("*_suffix", "item_suffix"));
    }

    #[test]
    fn test_path_filter() {
        let mut filter = PathFilter::new();
        filter.add_exclude("*.tmp");
        filter.add_exclude(".git/**");
        filter.add_include("keep.tmp");

        assert!(filter.is_excluded("scratch.tmp"));
        assert!(!filter.is_excluded("keep.tmp"));
        assert!(filter.is_excluded(".git/objects/abc"));
        assert!(!filter.is_excluded("src/main.rs"));
    }

    #[test]
    fn test_delete_mode_parsing() {
        assert_eq!(DeleteMode::from_str("none").unwrap(), DeleteMode::None);
        assert_eq!(
            DeleteMode::from_str("delete-before").unwrap(),
            DeleteMode::DeleteBefore
        );
        assert_eq!(
            DeleteMode::from_str("delete-after").unwrap(),
            DeleteMode::DeleteAfter
        );
        assert_eq!(
            DeleteMode::from_str("delete-excluded").unwrap(),
            DeleteMode::DeleteExcluded
        );
    }

    #[test]
    fn test_delete_guardrails() {
        let guardrails = DeleteGuardrails {
            max_delete_files: Some(5),
            max_delete_pct: Some(20.0),
            force_delete: false,
        };

        // Allowed: 2 of 20 files (10%)
        assert!(guardrails.validate_deletions(20, 2).is_ok());

        // Exceeds count: 6 files > 5
        let err_count = guardrails.validate_deletions(100, 6).unwrap_err();
        match err_count {
            DeleteSafetyError::MaxFilesExceeded { attempted, limit } => {
                assert_eq!(attempted, 6);
                assert_eq!(limit, 5);
            }
            _ => panic!("unexpected error type"),
        }

        // Exceeds percentage: 3 files out of 10 = 30% > 20%
        let err_pct = guardrails.validate_deletions(10, 3).unwrap_err();
        match err_pct {
            DeleteSafetyError::MaxPercentageExceeded {
                attempted_pct,
                limit_pct,
            } => {
                assert_eq!(attempted_pct, 30.0);
                assert_eq!(limit_pct, 20.0);
            }
            _ => panic!("unexpected error type"),
        }

        // Force delete overrides both
        let forced = guardrails.with_force_delete(true);
        assert!(forced.validate_deletions(10, 9).is_ok());
    }

    #[test]
    fn test_validate_deletion_path() {
        let root = Path::new("/tmp/velcrux_test");
        assert!(DeleteGuardrails::validate_deletion_path("sub/file.txt", root).is_ok());
        assert!(DeleteGuardrails::validate_deletion_path("data.bin", root).is_ok());

        // Path escapes
        assert!(DeleteGuardrails::validate_deletion_path("../escape.txt", root).is_err());
        assert!(DeleteGuardrails::validate_deletion_path("/etc/passwd", root).is_err());
        assert!(DeleteGuardrails::validate_deletion_path("", root).is_err());
        assert!(DeleteGuardrails::validate_deletion_path(".", root).is_err());

        // Protected Velcrux directories
        assert!(DeleteGuardrails::validate_deletion_path(".velcrux-staging/foo", root).is_err());
        assert!(DeleteGuardrails::validate_deletion_path(".velcrux-chunks/bar", root).is_err());
    }
}
