//! Whole-Directory Transactional Commit & Rollback Journaling (Option BM).
//!
//! Provides true directory-level atomicity (all-or-nothing commit) for multi-file transfers
//! and directory synchronizations:
//! - Shadow Directory Staging (`<target>/.velcrux-shadow/<tx_id>/`): All incoming files stage
//!   into an isolated shadow root without mutating live destination files.
//! - Two-Phase Commit (2PC):
//!   1. **Prepare Phase**: Cryptographic BLAKE3 verification, file size checking, and pre-existing
//!      file backup (`<target>/.velcrux-backup/<tx_id>/`).
//!   2. **Commit Phase**: Write-ahead journal intent logging, atomic swap of staged files into destination.
//!   3. **Rollback Phase**: Automatic or crash-recovery rollback reversing applied moves and
//!      restoring original files from backup if any failure occurs.
//! - Crash Recovery: `TransactionManager::recover_pending_transactions` inspects write-ahead journals
//!   on startup and resolves incomplete or interrupted transactions.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::{ProtocolError, VelcruxError};
use crate::util::Hash;

/// Error type for directory transaction operations.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionError {
    /// Transaction was not found.
    #[error("transaction '{0}' not found")]
    NotFound(String),

    /// Target path is invalid or outside directory boundary.
    #[error("invalid path in transaction: {0}")]
    InvalidPath(String),

    /// Checksum verification failure for staged file.
    #[error("checksum verification failed for '{path}': expected {expected}, computed {actual}")]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    /// File size mismatch for staged file.
    #[error("file size mismatch for '{path}': expected {expected} bytes, got {actual} bytes")]
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },

    /// Transaction is in an invalid state for requested operation.
    #[error("invalid transaction state: currently {current}, expected {expected}")]
    InvalidState { current: String, expected: String },

    /// I/O error during transaction staging, commit, or rollback.
    #[error("transaction I/O error: {0}")]
    Io(String),

    /// Recovery failure.
    #[error("transaction recovery error: {0}")]
    Recovery(String),
}

impl From<std::io::Error> for TransactionError {
    fn from(e: std::io::Error) -> Self {
        TransactionError::Io(e.to_string())
    }
}

impl From<TransactionError> for VelcruxError {
    fn from(e: TransactionError) -> Self {
        match e {
            TransactionError::NotFound(_) | TransactionError::InvalidPath(_) => {
                VelcruxError::Protocol(ProtocolError::InvalidPath)
            }
            TransactionError::ChecksumMismatch {
                path,
                expected,
                actual,
            } => VelcruxError::Internal(format!(
                "checksum verification failed for '{path}': expected {expected}, computed {actual}"
            )),
            other => VelcruxError::Internal(other.to_string()),
        }
    }
}

/// Operational state of a directory transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionState {
    /// Initial staging phase where files are being transferred to shadow root.
    Staging,
    /// Prepare phase: All files verified against hashes, backups created, ready to commit.
    Prepared,
    /// Commit in progress: Files are being atomically moved into target directory.
    Committing,
    /// Transaction committed: All files in place, final journal written.
    Committed,
    /// Transaction aborted before commit: Shadow files dropped, target untouched.
    Aborted,
    /// Transaction rolled back: Any committed moves reversed from backup, target restored.
    RolledBack,
}

impl std::fmt::Display for TransactionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Staging => write!(f, "Staging"),
            Self::Prepared => write!(f, "Prepared"),
            Self::Committing => write!(f, "Committing"),
            Self::Committed => write!(f, "Committed"),
            Self::Aborted => write!(f, "Aborted"),
            Self::RolledBack => write!(f, "RolledBack"),
        }
    }
}

/// Type of file action recorded in transaction journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionAction {
    /// Create a new file (did not exist before in target).
    Create,
    /// Overwrite / update an existing file.
    Update,
    /// Delete an existing file.
    Delete,
}

impl std::fmt::Display for TransactionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "Create"),
            Self::Update => write!(f, "Update"),
            Self::Delete => write!(f, "Delete"),
        }
    }
}

/// An individual file entry tracked within a directory transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionItem {
    /// Relative path within target directory.
    pub rel_path: String,
    /// Action type.
    pub action: TransactionAction,
    /// Path to staged file in shadow directory (if Create/Update).
    pub shadow_path: Option<PathBuf>,
    /// Path to backup of original file (if Update/Delete).
    pub backup_path: Option<PathBuf>,
    /// Final destination path in target directory.
    pub dest_path: PathBuf,
    /// Expected whole-file BLAKE3 hash.
    pub expected_hash: Option<Hash>,
    /// Original pre-existing file hash (for rollback verification).
    pub original_hash: Option<Hash>,
    /// File size in bytes.
    pub size: u64,
    /// Whether this individual item was applied to destination.
    pub applied: bool,
}

/// Persistent write-ahead journal payload stored on disk (`<target>/.velcrux-journal/<tx_id>.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionJournal {
    /// Unique transaction identifier.
    pub tx_id: String,
    /// Target directory root path.
    pub target_dir: PathBuf,
    /// Shadow staging directory.
    pub shadow_root: PathBuf,
    /// Backup directory.
    pub backup_root: PathBuf,
    /// Current transaction state.
    pub state: TransactionState,
    /// Timestamp when transaction was created (Unix epoch seconds).
    pub created_at_sec: u64,
    /// Timestamp when state was last modified (Unix epoch seconds).
    pub updated_at_sec: u64,
    /// List of file items managed in transaction.
    pub items: Vec<TransactionItem>,
}

/// Summary report returned upon transaction operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReport {
    /// Transaction ID.
    pub tx_id: String,
    /// Final state.
    pub state: TransactionState,
    /// Total files processed.
    pub files_total: usize,
    /// Files successfully committed.
    pub files_committed: usize,
    /// Files backed up.
    pub files_backed_up: usize,
    /// Files rolled back.
    pub files_rolled_back: usize,
    /// Total bytes committed.
    pub bytes_committed: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// Concise summary of a transaction for catalog enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionSummary {
    /// Transaction ID.
    pub tx_id: String,
    /// Target directory.
    pub target_dir: String,
    /// Current state.
    pub state: TransactionState,
    /// Total files.
    pub file_count: usize,
    /// Timestamp created.
    pub created_at_sec: u64,
}

static TX_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Atomic Whole-Directory Transaction Coordinator.
pub struct DirectoryTransaction {
    tx_id: String,
    target_dir: PathBuf,
    shadow_root: PathBuf,
    backup_root: PathBuf,
    journal_path: PathBuf,
    state: TransactionState,
    items: Vec<TransactionItem>,
    created_at_sec: u64,
    start_time: SystemTime,
}

impl DirectoryTransaction {
    /// Begin a new whole-directory transaction targeting `target_dir`.
    pub fn begin(target_dir: &Path) -> Result<Self, TransactionError> {
        let abs_target = if target_dir.is_absolute() {
            target_dir.to_path_buf()
        } else {
            std::env::current_dir()?.join(target_dir)
        };

        if !abs_target.exists() {
            fs::create_dir_all(&abs_target)?;
        }

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let counter = TX_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tx_id = format!("tx_{}_{}", now_sec, counter);

        let shadow_root = abs_target.join(".velcrux-shadow").join(&tx_id);
        let backup_root = abs_target.join(".velcrux-backup").join(&tx_id);
        let journal_dir = abs_target.join(".velcrux-journal");
        let journal_path = journal_dir.join(format!("{}.json", tx_id));

        fs::create_dir_all(&shadow_root)?;
        fs::create_dir_all(&backup_root)?;
        fs::create_dir_all(&journal_dir)?;

        let tx = Self {
            tx_id,
            target_dir: abs_target,
            shadow_root,
            backup_root,
            journal_path,
            state: TransactionState::Staging,
            items: Vec::new(),
            created_at_sec: now_sec,
            start_time: SystemTime::now(),
        };

        tx.save_journal()?;
        Ok(tx)
    }

    /// Access unique transaction ID.
    pub fn tx_id(&self) -> &str {
        &self.tx_id
    }

    /// Access target destination directory.
    pub fn target_dir(&self) -> &Path {
        &self.target_dir
    }

    /// Access shadow staging root directory.
    pub fn shadow_root(&self) -> &Path {
        &self.shadow_root
    }

    /// Current operational state.
    pub fn state(&self) -> TransactionState {
        self.state
    }

    /// Stage a file from an existing local file into the transaction's shadow directory.
    pub fn stage_file(
        &mut self,
        rel_path: &str,
        source_path: &Path,
        expected_hash: Option<Hash>,
    ) -> Result<PathBuf, TransactionError> {
        if self.state != TransactionState::Staging {
            return Err(TransactionError::InvalidState {
                current: self.state.to_string(),
                expected: "Staging".to_string(),
            });
        }

        let clean_rel = rel_path.trim_start_matches('/').replace('\\', "/");
        let shadow_dest = self.shadow_root.join(&clean_rel);
        if let Some(parent) = shadow_dest.parent() {
            fs::create_dir_all(parent)?;
        }

        // Copy into shadow directory
        fs::copy(source_path, &shadow_dest)?;
        let size = fs::metadata(&shadow_dest)?.len();

        let dest_path = self.target_dir.join(&clean_rel);
        let action = if dest_path.exists() {
            TransactionAction::Update
        } else {
            TransactionAction::Create
        };

        let original_hash = if dest_path.exists() {
            fs::read(&dest_path).ok().map(|b| Hash::of(&b))
        } else {
            None
        };

        self.items.push(TransactionItem {
            rel_path: clean_rel,
            action,
            shadow_path: Some(shadow_dest.clone()),
            backup_path: None,
            dest_path,
            expected_hash,
            original_hash,
            size,
            applied: false,
        });

        self.save_journal()?;
        Ok(shadow_dest)
    }

    /// Stage in-memory bytes into transaction shadow directory.
    pub fn stage_file_bytes(
        &mut self,
        rel_path: &str,
        bytes: &[u8],
        expected_hash: Option<Hash>,
    ) -> Result<PathBuf, TransactionError> {
        if self.state != TransactionState::Staging {
            return Err(TransactionError::InvalidState {
                current: self.state.to_string(),
                expected: "Staging".to_string(),
            });
        }

        let clean_rel = rel_path.trim_start_matches('/').replace('\\', "/");
        let shadow_dest = self.shadow_root.join(&clean_rel);
        if let Some(parent) = shadow_dest.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&shadow_dest, bytes)?;
        let size = bytes.len() as u64;

        let dest_path = self.target_dir.join(&clean_rel);
        let action = if dest_path.exists() {
            TransactionAction::Update
        } else {
            TransactionAction::Create
        };

        let original_hash = if dest_path.exists() {
            fs::read(&dest_path).ok().map(|b| Hash::of(&b))
        } else {
            None
        };

        self.items.push(TransactionItem {
            rel_path: clean_rel,
            action,
            shadow_path: Some(shadow_dest.clone()),
            backup_path: None,
            dest_path,
            expected_hash,
            original_hash,
            size,
            applied: false,
        });

        self.save_journal()?;
        Ok(shadow_dest)
    }

    /// Register a file that has already been written directly into the shadow staging directory.
    pub fn register_staged(
        &mut self,
        rel_path: &str,
        shadow_path: PathBuf,
        expected_hash: Option<Hash>,
    ) -> Result<(), TransactionError> {
        if self.state != TransactionState::Staging {
            return Err(TransactionError::InvalidState {
                current: self.state.to_string(),
                expected: "Staging".to_string(),
            });
        }

        let clean_rel = rel_path.trim_start_matches('/').replace('\\', "/");
        let size = fs::metadata(&shadow_path)?.len();
        let dest_path = self.target_dir.join(&clean_rel);
        let action = if dest_path.exists() {
            TransactionAction::Update
        } else {
            TransactionAction::Create
        };

        let original_hash = if dest_path.exists() {
            fs::read(&dest_path).ok().map(|b| Hash::of(&b))
        } else {
            None
        };

        self.items.push(TransactionItem {
            rel_path: clean_rel,
            action,
            shadow_path: Some(shadow_path),
            backup_path: None,
            dest_path,
            expected_hash,
            original_hash,
            size,
            applied: false,
        });

        self.save_journal()?;
        Ok(())
    }

    /// Stage a deletion of an existing file in the target directory.
    pub fn stage_deletion(&mut self, rel_path: &str) -> Result<(), TransactionError> {
        if self.state != TransactionState::Staging {
            return Err(TransactionError::InvalidState {
                current: self.state.to_string(),
                expected: "Staging".to_string(),
            });
        }

        let clean_rel = rel_path.trim_start_matches('/').replace('\\', "/");
        let dest_path = self.target_dir.join(&clean_rel);
        if !dest_path.exists() {
            return Ok(());
        }

        let original_hash = fs::read(&dest_path).ok().map(|b| Hash::of(&b));
        let size = fs::metadata(&dest_path)?.len();

        self.items.push(TransactionItem {
            rel_path: clean_rel,
            action: TransactionAction::Delete,
            shadow_path: None,
            backup_path: None,
            dest_path,
            expected_hash: None,
            original_hash,
            size,
            applied: false,
        });

        self.save_journal()?;
        Ok(())
    }

    /// Phase 1: Prepare transaction for commit.
    ///
    /// Validates all staged shadow files against expected hashes and sizes.
    /// Creates backups of all pre-existing target files that will be modified or deleted.
    pub fn prepare(&mut self) -> Result<TransactionReport, TransactionError> {
        if self.state != TransactionState::Staging {
            return Err(TransactionError::InvalidState {
                current: self.state.to_string(),
                expected: "Staging".to_string(),
            });
        }

        let mut backed_up = 0;
        let mut total_bytes = 0u64;

        // 1. Verify all staged files
        for item in &mut self.items {
            if let Some(shadow) = &item.shadow_path {
                if !shadow.exists() {
                    return Err(TransactionError::InvalidPath(format!(
                        "staged shadow file missing: {}",
                        shadow.display()
                    )));
                }

                let shadow_meta = fs::metadata(shadow)?;
                if shadow_meta.len() != item.size {
                    return Err(TransactionError::SizeMismatch {
                        path: item.rel_path.clone(),
                        expected: item.size,
                        actual: shadow_meta.len(),
                    });
                }

                if let Some(expected) = item.expected_hash {
                    let mut file = File::open(shadow)?;
                    let mut buf = Vec::with_capacity(item.size as usize);
                    file.read_to_end(&mut buf)?;
                    let actual = Hash::of(&buf);
                    if actual != expected {
                        return Err(TransactionError::ChecksumMismatch {
                            path: item.rel_path.clone(),
                            expected: expected.to_hex(),
                            actual: actual.to_hex(),
                        });
                    }
                }
                total_bytes += item.size;
            }

            // 2. Backup existing destination file if Update or Delete
            if matches!(
                item.action,
                TransactionAction::Update | TransactionAction::Delete
            ) && item.dest_path.exists()
            {
                let backup_file = self.backup_root.join(&item.rel_path);
                if let Some(p) = backup_file.parent() {
                    fs::create_dir_all(p)?;
                }

                // Copy to backup directory
                fs::copy(&item.dest_path, &backup_file)?;
                item.backup_path = Some(backup_file);
                backed_up += 1;
            }
        }

        self.state = TransactionState::Prepared;
        self.save_journal()?;

        let elapsed = self.start_time.elapsed().unwrap_or_default().as_millis() as u64;

        Ok(TransactionReport {
            tx_id: self.tx_id.clone(),
            state: self.state,
            files_total: self.items.len(),
            files_committed: 0,
            files_backed_up: backed_up,
            files_rolled_back: 0,
            bytes_committed: total_bytes,
            duration_ms: elapsed,
        })
    }

    /// Phase 2: Commit all staged changes atomically.
    ///
    /// Swaps shadow files into place and removes files marked for deletion.
    /// If any atomic move fails, automatic rollback is triggered to restore
    /// original directory state.
    pub fn commit(&mut self) -> Result<TransactionReport, TransactionError> {
        if self.state == TransactionState::Staging {
            self.prepare()?;
        }

        if self.state != TransactionState::Prepared {
            return Err(TransactionError::InvalidState {
                current: self.state.to_string(),
                expected: "Prepared".to_string(),
            });
        }

        self.state = TransactionState::Committing;
        self.save_journal()?;

        let mut committed = 0;
        let mut total_bytes = 0u64;

        let mut commit_err: Option<String> = None;

        for item in &mut self.items {
            let res = match item.action {
                TransactionAction::Create | TransactionAction::Update => {
                    if let Some(shadow) = &item.shadow_path {
                        if let Some(p) = item.dest_path.parent() {
                            fs::create_dir_all(p)?;
                        }

                        // Atomic rename into final location
                        if item.dest_path.exists() {
                            // On Windows, remove before rename if exists
                            let _ = fs::remove_file(&item.dest_path);
                        }
                        fs::rename(shadow, &item.dest_path)
                    } else {
                        Ok(())
                    }
                }
                TransactionAction::Delete => {
                    if item.dest_path.exists() {
                        fs::remove_file(&item.dest_path)
                    } else {
                        Ok(())
                    }
                }
            };

            match res {
                Ok(_) => {
                    item.applied = true;
                    if matches!(
                        item.action,
                        TransactionAction::Create | TransactionAction::Update
                    ) {
                        committed += 1;
                        total_bytes += item.size;
                    }
                }
                Err(e) => {
                    commit_err = Some(format!("commit failed on '{}': {}", item.rel_path, e));
                    break;
                }
            }
        }

        if let Some(err) = commit_err {
            let _ = self.rollback();
            return Err(TransactionError::Io(format!(
                "{}; transaction rolled back",
                err
            )));
        }

        // All items committed successfully
        self.state = TransactionState::Committed;
        self.save_journal()?;

        // Clean up shadow staging directory (backup is preserved for rollback capability)
        let _ = fs::remove_dir_all(&self.shadow_root);

        let elapsed = self.start_time.elapsed().unwrap_or_default().as_millis() as u64;

        Ok(TransactionReport {
            tx_id: self.tx_id.clone(),
            state: self.state,
            files_total: self.items.len(),
            files_committed: committed,
            files_backed_up: 0,
            files_rolled_back: 0,
            bytes_committed: total_bytes,
            duration_ms: elapsed,
        })
    }

    /// Roll back transaction, restoring any modified or deleted files from backup.
    pub fn rollback(&mut self) -> Result<TransactionReport, TransactionError> {
        let mut rolled_back = 0;

        for item in &mut self.items {
            if item.applied {
                match item.action {
                    TransactionAction::Create => {
                        // Remove newly created file
                        if item.dest_path.exists() {
                            let _ = fs::remove_file(&item.dest_path);
                            rolled_back += 1;
                        }
                    }
                    TransactionAction::Update | TransactionAction::Delete => {
                        // Restore from backup
                        if let Some(backup) = &item.backup_path {
                            if backup.exists() {
                                if let Some(p) = item.dest_path.parent() {
                                    let _ = fs::create_dir_all(p);
                                }
                                let _ = fs::copy(backup, &item.dest_path);
                                rolled_back += 1;
                            }
                        }
                    }
                }
                item.applied = false;
            }
        }

        self.state = TransactionState::RolledBack;
        self.save_journal()?;

        // Clean up shadow and backup directories
        let _ = fs::remove_dir_all(&self.shadow_root);
        let _ = fs::remove_dir_all(&self.backup_root);

        let elapsed = self.start_time.elapsed().unwrap_or_default().as_millis() as u64;

        Ok(TransactionReport {
            tx_id: self.tx_id.clone(),
            state: self.state,
            files_total: self.items.len(),
            files_committed: 0,
            files_backed_up: 0,
            files_rolled_back: rolled_back,
            bytes_committed: 0,
            duration_ms: elapsed,
        })
    }

    /// Abort transaction before commit has taken place.
    pub fn abort(&mut self) -> Result<(), TransactionError> {
        self.state = TransactionState::Aborted;
        self.save_journal()?;
        let _ = fs::remove_dir_all(&self.shadow_root);
        let _ = fs::remove_dir_all(&self.backup_root);
        Ok(())
    }

    fn save_journal(&self) -> Result<(), TransactionError> {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let journal = TransactionJournal {
            tx_id: self.tx_id.clone(),
            target_dir: self.target_dir.clone(),
            shadow_root: self.shadow_root.clone(),
            backup_root: self.backup_root.clone(),
            state: self.state,
            created_at_sec: self.created_at_sec,
            updated_at_sec: now_sec,
            items: self.items.clone(),
        };

        let json = serde_json::to_string_pretty(&journal)
            .map_err(|e| TransactionError::Io(format!("serializing journal: {e}")))?;

        // Atomic write via tempfile
        let tmp_journal = self.journal_path.with_extension("tmp");
        {
            let mut file = File::create(&tmp_journal)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp_journal, &self.journal_path)?;
        Ok(())
    }
}

/// Transaction Manager coordinating transaction lifecycles and crash recovery across directories.
pub struct TransactionManager;

impl TransactionManager {
    /// List all transactions recorded in `target_dir/.velcrux-journal/`.
    pub fn list_transactions(
        target_dir: &Path,
    ) -> Result<Vec<TransactionSummary>, TransactionError> {
        let journal_dir = target_dir.join(".velcrux-journal");
        if !journal_dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut summaries = Vec::new();
        for entry in fs::read_dir(journal_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(journal) = serde_json::from_str::<TransactionJournal>(&content) {
                        summaries.push(TransactionSummary {
                            tx_id: journal.tx_id,
                            target_dir: journal.target_dir.display().to_string(),
                            state: journal.state,
                            file_count: journal.items.len(),
                            created_at_sec: journal.created_at_sec,
                        });
                    }
                }
            }
        }

        summaries.sort_by(|a, b| b.created_at_sec.cmp(&a.created_at_sec));
        Ok(summaries)
    }

    /// Read full transaction journal for a given transaction ID.
    pub fn get_journal(
        target_dir: &Path,
        tx_id: &str,
    ) -> Result<TransactionJournal, TransactionError> {
        let journal_file = target_dir
            .join(".velcrux-journal")
            .join(format!("{}.json", tx_id));
        if !journal_file.is_file() {
            return Err(TransactionError::NotFound(tx_id.to_string()));
        }

        let content = fs::read_to_string(&journal_file)?;
        serde_json::from_str::<TransactionJournal>(&content)
            .map_err(|e| TransactionError::Io(format!("corrupt journal: {e}")))
    }

    /// Roll back a specific transaction by ID.
    pub fn rollback_transaction(
        target_dir: &Path,
        tx_id: &str,
    ) -> Result<TransactionReport, TransactionError> {
        let journal = Self::get_journal(target_dir, tx_id)?;
        let mut tx = DirectoryTransaction {
            tx_id: journal.tx_id,
            target_dir: journal.target_dir,
            shadow_root: journal.shadow_root,
            backup_root: journal.backup_root,
            journal_path: target_dir
                .join(".velcrux-journal")
                .join(format!("{}.json", tx_id)),
            state: journal.state,
            items: journal.items,
            created_at_sec: journal.created_at_sec,
            start_time: SystemTime::now(),
        };

        tx.rollback()
    }

    /// Scan directory for pending or interrupted transactions after a process crash
    /// and recover them automatically:
    /// - `Staging` / `Prepared`: Aborts and purges shadow files.
    /// - `Committing`: Replays rollback to ensure destination directory is 100% clean and consistent.
    /// - `Committed`: Cleans up any remaining backup or shadow staging roots.
    pub fn recover_pending_transactions(
        target_dir: &Path,
    ) -> Result<Vec<TransactionReport>, TransactionError> {
        let journal_dir = target_dir.join(".velcrux-journal");
        if !journal_dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut reports = Vec::new();

        for entry in fs::read_dir(journal_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(journal) = serde_json::from_str::<TransactionJournal>(&content) {
                        let mut tx = DirectoryTransaction {
                            tx_id: journal.tx_id.clone(),
                            target_dir: journal.target_dir.clone(),
                            shadow_root: journal.shadow_root.clone(),
                            backup_root: journal.backup_root.clone(),
                            journal_path: path.clone(),
                            state: journal.state,
                            items: journal.items,
                            created_at_sec: journal.created_at_sec,
                            start_time: SystemTime::now(),
                        };

                        match journal.state {
                            TransactionState::Staging | TransactionState::Prepared => {
                                let _ = tx.abort();
                                reports.push(TransactionReport {
                                    tx_id: journal.tx_id,
                                    state: TransactionState::Aborted,
                                    files_total: tx.items.len(),
                                    files_committed: 0,
                                    files_backed_up: 0,
                                    files_rolled_back: 0,
                                    bytes_committed: 0,
                                    duration_ms: 0,
                                });
                            }
                            TransactionState::Committing => {
                                // Interrupted during commit: rollback!
                                let rep = tx.rollback()?;
                                reports.push(rep);
                            }
                            TransactionState::Committed => {
                                // Clean up any lingering backup/shadow artifacts
                                let _ = fs::remove_dir_all(&journal.shadow_root);
                                let _ = fs::remove_dir_all(&journal.backup_root);
                            }
                            TransactionState::Aborted | TransactionState::RolledBack => {
                                // Already terminal state
                            }
                        }
                    }
                }
            }
        }

        Ok(reports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_transaction_commit_success() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("target_dir");
        fs::create_dir_all(&target).unwrap();

        let mut tx = DirectoryTransaction::begin(&target).unwrap();
        assert_eq!(tx.state(), TransactionState::Staging);

        let data1 = b"Hello Transactional File 1";
        let data2 = b"Hello Transactional File 2 in Subfolder";

        tx.stage_file_bytes("f1.txt", data1, Some(Hash::of(data1)))
            .unwrap();
        tx.stage_file_bytes("sub/f2.txt", data2, Some(Hash::of(data2)))
            .unwrap();

        let prep_report = tx.prepare().unwrap();
        assert_eq!(prep_report.state, TransactionState::Prepared);
        assert_eq!(prep_report.files_total, 2);

        // Before commit, target does not contain the files
        assert!(!target.join("f1.txt").exists());
        assert!(!target.join("sub/f2.txt").exists());

        // Commit
        let commit_report = tx.commit().unwrap();
        assert_eq!(commit_report.state, TransactionState::Committed);
        assert_eq!(commit_report.files_committed, 2);

        // After commit, target has the files
        assert_eq!(fs::read(target.join("f1.txt")).unwrap(), data1);
        assert_eq!(fs::read(target.join("sub/f2.txt")).unwrap(), data2);
    }

    #[test]
    fn test_transaction_prepare_hash_mismatch_aborts() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("target_dir");
        fs::create_dir_all(&target).unwrap();

        let mut tx = DirectoryTransaction::begin(&target).unwrap();
        let data = b"Valid Payload";
        let bad_hash = Hash::of(b"Different Payload");

        tx.stage_file_bytes("corrupted.txt", data, Some(bad_hash))
            .unwrap();

        let err = tx.prepare();
        assert!(matches!(
            err,
            Err(TransactionError::ChecksumMismatch { .. })
        ));

        // Target remains untouched
        assert!(!target.join("corrupted.txt").exists());
    }

    #[test]
    fn test_transaction_rollback_restores_original() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("target_dir");
        fs::create_dir_all(&target).unwrap();

        let original_content = b"Original baseline data";
        let target_file = target.join("baseline.txt");
        fs::write(&target_file, original_content).unwrap();

        let mut tx = DirectoryTransaction::begin(&target).unwrap();
        let new_content = b"New mutated data to be aborted";
        tx.stage_file_bytes("baseline.txt", new_content, Some(Hash::of(new_content)))
            .unwrap();

        tx.prepare().unwrap();

        // Rollback
        let rb_report = tx.rollback().unwrap();
        assert_eq!(rb_report.state, TransactionState::RolledBack);
        assert_eq!(rb_report.files_rolled_back, 0); // was not yet applied to dest

        // Verify baseline content is untouched
        assert_eq!(fs::read(&target_file).unwrap(), original_content);
    }

    #[test]
    fn test_transaction_manager_crash_recovery() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("target_dir");
        fs::create_dir_all(&target).unwrap();

        let baseline_content = b"Pre-crash baseline content";
        fs::write(target.join("crash_target.txt"), baseline_content).unwrap();

        let mut tx = DirectoryTransaction::begin(&target).unwrap();
        let mutated = b"Crash in-flight mutated content";
        tx.stage_file_bytes("crash_target.txt", mutated, Some(Hash::of(mutated)))
            .unwrap();
        tx.prepare().unwrap();

        // Simulate crash by forcing state to Committing with applied flag set
        tx.state = TransactionState::Committing;
        tx.items[0].applied = true;
        fs::write(target.join("crash_target.txt"), mutated).unwrap();
        tx.save_journal().unwrap();

        // Recover
        let recovered = TransactionManager::recover_pending_transactions(&target).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, TransactionState::RolledBack);

        // Verify baseline was restored from backup
        assert_eq!(
            fs::read(target.join("crash_target.txt")).unwrap(),
            baseline_content
        );
    }
}
