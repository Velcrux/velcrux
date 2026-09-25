//! SQLite-backed `StateStore`. The production implementation per
//! `ADR-005` (one DB per role, absolute path, WAL mode).
//!
//! The DB connection is held in an `Arc<Mutex<Connection>>`; all
//! operations take the lock. The single-writer / multi-reader pattern
//! of WAL is exactly what we need because the transfer engine is a
//! per-connection state machine that does not contend with itself.
//!
//! ## Schema (v1)
//!
//! - `transfers(role, idempotency_key)` UNIQUE — idempotency index.
//! - `transfers(transfer_id)` UNIQUE — primary handle.
//! - `chunk_bitmap(transfer_id, chunk_index)` — sparse completion rows.
//! - `commit_journal(transfer_id, file_id)` UNIQUE — atomic-commit
//!   recovery midpoint.
//!
//! All `INTEGER` columns that are wire sizes are `INTEGER` (64-bit on
//! SQLite's dynamic typing). `file_hash` is `BLOB` (32 bytes).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::util::TransferId;

use super::bitmap::ChunkBitmap;
use super::{
    CommitJournalEntry, CommitStatus, Direction, JournalRecovery, Role, StateStore,
    StateStoreError, StateStoreResult, TransferRecord, TransferStatus, UpsertOutcome,
};

/// Current schema version. Bumped by hand when migrations are added.
const SCHEMA_VERSION: i32 = 1;

/// `Mutex` that returns `Database` on poison.
fn lock_db(
    g: std::sync::LockResult<MutexGuard<'_, Connection>>,
) -> StateStoreResult<MutexGuard<'_, Connection>> {
    match g {
        Ok(g) => Ok(g),
        Err(p) => Err(StateStoreError::Database(format!(
            "sqlite mutex poisoned: {p}"
        ))),
    }
}

/// SQLite-backed `StateStore`. Opens (and migrates) the DB in `new`.
pub struct SqliteStateStore {
    conn: Arc<Mutex<Connection>>,
    /// Cached absolute path. Surfaced in error messages.
    path: PathBuf,
}

impl SqliteStateStore {
    /// Open or create the DB at `path`. The path **must be absolute**
    /// per `ADR-005`: a relative path combined with a working-directory
    /// change silently creates a fresh empty DB and loses resume state.
    pub fn new(path: impl AsRef<Path>) -> StateStoreResult<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_absolute() {
            return Err(StateStoreError::Database(format!(
                "state DB path must be absolute (ADR-005); got {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                StateStoreError::Database(format!("create_dir_all({}): {e}", parent.display()))
            })?;
        }
        let conn = Connection::open(&path)
            .map_err(|e| StateStoreError::Database(format!("open {}: {e}", path.display())))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| StateStoreError::Database(format!("pragma journal_mode: {e}")))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| StateStoreError::Database(format!("pragma synchronous: {e}")))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| StateStoreError::Database(format!("pragma foreign_keys: {e}")))?;
        conn.pragma_update(None, "temp_store", "MEMORY")
            .map_err(|e| StateStoreError::Database(format!("pragma temp_store: {e}")))?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
        };
        store.migrate()?;
        Ok(store)
    }

    /// Path the DB was opened at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn migrate(&self) -> StateStoreResult<()> {
        let g = lock_db(self.conn.lock())?;
        let current: i32 = g
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|e| StateStoreError::Database(format!("PRAGMA user_version: {e}")))?;
        if current == 0 {
            g.execute_batch(SCHEMA_V1)
                .map_err(|e| StateStoreError::Database(format!("schema v1: {e}")))?;
            g.pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(|e| StateStoreError::Database(format!("user_version: {e}")))?;
        } else if current != SCHEMA_VERSION {
            return Err(StateStoreError::Database(format!(
                "state DB schema is v{current}, this binary expects v{SCHEMA_VERSION}"
            )));
        }
        Ok(())
    }
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS transfers (
    transfer_id         BLOB PRIMARY KEY,
    role                INTEGER NOT NULL,
    idempotency_key     TEXT NOT NULL,
    direction           INTEGER NOT NULL,
    status              TEXT NOT NULL,
    remote_path         TEXT NOT NULL,
    local_path          TEXT NOT NULL,
    file_size           INTEGER NOT NULL,
    file_hash           BLOB NOT NULL,
    verified_up_to      INTEGER NOT NULL DEFAULT 0,
    last_checkpoint_ms  INTEGER NOT NULL DEFAULT 0,
    bytes_completed     INTEGER NOT NULL DEFAULT 0,
    staging_relpath     TEXT NOT NULL DEFAULT '',
    created_ms          INTEGER NOT NULL,
    updated_ms          INTEGER NOT NULL,
    UNIQUE (role, idempotency_key)
);

CREATE INDEX IF NOT EXISTS transfers_remote_path_idx
    ON transfers (role, remote_path);

CREATE TABLE IF NOT EXISTS chunk_bitmap (
    transfer_id  BLOB NOT NULL,
    chunk_index  INTEGER NOT NULL,
    PRIMARY KEY (transfer_id, chunk_index),
    FOREIGN KEY (transfer_id) REFERENCES transfers(transfer_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS commit_journal (
    transfer_id  BLOB NOT NULL,
    file_id      INTEGER NOT NULL,
    remote_path  TEXT NOT NULL,
    status       TEXT NOT NULL,
    updated_ms   INTEGER NOT NULL,
    PRIMARY KEY (transfer_id, file_id),
    FOREIGN KEY (transfer_id) REFERENCES transfers(transfer_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS commit_journal_status_idx
    ON commit_journal (status);
"#;

fn role_to_int(r: Role) -> i32 {
    match r {
        Role::Client => 1,
        Role::Server => 2,
    }
}

fn int_to_role(v: i32) -> StateStoreResult<Role> {
    match v {
        1 => Ok(Role::Client),
        2 => Ok(Role::Server),
        _ => Err(StateStoreError::Corrupt(format!("unknown role value: {v}"))),
    }
}

fn direction_to_int(d: Direction) -> i32 {
    match d {
        Direction::Upload => 1,
        Direction::Download => 2,
    }
}

fn int_to_direction(v: i32) -> StateStoreResult<Direction> {
    match v {
        1 => Ok(Direction::Upload),
        2 => Ok(Direction::Download),
        _ => Err(StateStoreError::Corrupt(format!(
            "unknown direction value: {v}"
        ))),
    }
}

fn status_to_str(s: TransferStatus) -> &'static str {
    match s {
        TransferStatus::Active => "active",
        TransferStatus::Cancelled => "cancelled",
        TransferStatus::Committed => "committed",
        TransferStatus::Resumable => "resumable",
    }
}

fn str_to_status(s: &str) -> StateStoreResult<TransferStatus> {
    match s {
        "active" => Ok(TransferStatus::Active),
        "cancelled" => Ok(TransferStatus::Cancelled),
        "committed" => Ok(TransferStatus::Committed),
        "resumable" => Ok(TransferStatus::Resumable),
        _ => Err(StateStoreError::Corrupt(format!("unknown status: {s}"))),
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<TransferRecord> {
    let tid_blob: Vec<u8> = row.get("transfer_id")?;
    let tid = TransferId::from_bytes(&tid_blob).ok_or_else(|| rusqlite::Error::InvalidQuery)?;
    let role: i32 = row.get("role")?;
    let direction: i32 = row.get("direction")?;
    let status: String = row.get("status")?;
    let file_hash: Vec<u8> = row.get("file_hash")?;
    let file_hash =
        crate::util::Hash::from_bytes(&file_hash).ok_or_else(|| rusqlite::Error::InvalidQuery)?;
    let r = int_to_role(role).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let d = int_to_direction(direction).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let s = str_to_status(&status).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(TransferRecord {
        transfer_id: tid,
        idempotency_key: row.get("idempotency_key")?,
        role: r,
        direction: d,
        status: s,
        remote_path: row.get("remote_path")?,
        local_path: row.get("local_path")?,
        file_size: row.get::<_, i64>("file_size")? as u64,
        file_hash,
        verified_up_to: row.get::<_, i64>("verified_up_to")? as u64,
        last_checkpoint_ms: row.get::<_, i64>("last_checkpoint_ms")? as u64,
        bytes_completed: row.get::<_, i64>("bytes_completed")? as u64,
        staging_relpath: row.get("staging_relpath")?,
        created_ms: row.get::<_, i64>("created_ms")? as u64,
        updated_ms: row.get::<_, i64>("updated_ms")? as u64,
    })
}

/// Field list for SELECT/INSERT. Kept in one place to avoid drift.
const TRANSFER_COLS_LIST: &str = "transfer_id, role, idempotency_key, direction, status, \
    remote_path, local_path, file_size, file_hash, verified_up_to, \
    last_checkpoint_ms, bytes_completed, staging_relpath, created_ms, updated_ms";

fn insert_sql() -> String {
    format!("INSERT INTO transfers ({TRANSFER_COLS_LIST}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
}

fn update_sql() -> String {
    format!(
        "UPDATE transfers SET role=?, idempotency_key=?, direction=?, status=?, \
         remote_path=?, local_path=?, file_size=?, file_hash=?, verified_up_to=?, \
         last_checkpoint_ms=?, bytes_completed=?, staging_relpath=?, created_ms=?, updated_ms=? \
         WHERE transfer_id=?"
    )
}

fn bind_record(stmt: &mut rusqlite::Statement<'_>, r: &TransferRecord) -> StateStoreResult<()> {
    stmt.execute(params![
        r.transfer_id.as_bytes().as_slice(),
        role_to_int(r.role),
        r.idempotency_key,
        direction_to_int(r.direction),
        status_to_str(r.status),
        r.remote_path,
        r.local_path,
        r.file_size as i64,
        r.file_hash.as_bytes().as_slice(),
        r.verified_up_to as i64,
        r.last_checkpoint_ms as i64,
        r.bytes_completed as i64,
        r.staging_relpath,
        r.created_ms as i64,
        r.updated_ms as i64,
    ])
    .map_err(|e| StateStoreError::Database(format!("insert: {e}")))?;
    Ok(())
}

fn bind_update(stmt: &mut rusqlite::Statement<'_>, r: &TransferRecord) -> StateStoreResult<()> {
    stmt.execute(params![
        role_to_int(r.role),
        r.idempotency_key,
        direction_to_int(r.direction),
        status_to_str(r.status),
        r.remote_path,
        r.local_path,
        r.file_size as i64,
        r.file_hash.as_bytes().as_slice(),
        r.verified_up_to as i64,
        r.last_checkpoint_ms as i64,
        r.bytes_completed as i64,
        r.staging_relpath,
        r.created_ms as i64,
        r.updated_ms as i64,
        r.transfer_id.as_bytes().as_slice(),
    ])
    .map_err(|e| StateStoreError::Database(format!("update: {e}")))?;
    Ok(())
}

fn current_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl StateStore for SqliteStateStore {
    fn upsert_transfer(&self, record: &TransferRecord) -> StateStoreResult<UpsertOutcome> {
        let g = lock_db(self.conn.lock())?;
        // Look up by (role, idempotency_key) first. If present, verify
        // compatibility and return the existing row.
        let existing: Option<TransferRecord> = g
            .query_row(
                &format!(
                    "SELECT {TRANSFER_COLS_LIST} FROM transfers \
                     WHERE role=? AND idempotency_key=?"
                ),
                params![role_to_int(record.role), record.idempotency_key],
                row_to_record,
            )
            .optional()
            .map_err(|e| StateStoreError::Database(format!("query existing: {e}")))?;
        if let Some(e) = existing {
            if e.role != record.role
                || e.direction != record.direction
                || e.remote_path != record.remote_path
                || e.local_path != record.local_path
                || e.file_size != record.file_size
                || e.file_hash != record.file_hash
            {
                return Err(StateStoreError::IdempotencyConflict(format!(
                    "idempotency key '{}' already used by transfer {} with different parameters",
                    record.idempotency_key, e.transfer_id
                )));
            }
            return Ok(UpsertOutcome::Reused(e));
        }
        let mut stmt = g
            .prepare(&insert_sql())
            .map_err(|e| StateStoreError::Database(format!("prepare insert: {e}")))?;
        bind_record(&mut stmt, record)?;
        Ok(UpsertOutcome::Inserted)
    }

    fn update_transfer(&self, record: &TransferRecord) -> StateStoreResult<()> {
        let g = lock_db(self.conn.lock())?;
        let mut stmt = g
            .prepare(&update_sql())
            .map_err(|e| StateStoreError::Database(format!("prepare update: {e}")))?;
        bind_update(&mut stmt, record)?;
        // Verify the row existed.
        let exists: bool = g
            .query_row(
                "SELECT 1 FROM transfers WHERE transfer_id=?",
                params![record.transfer_id.as_bytes().as_slice()],
                |_r| Ok(true),
            )
            .optional()
            .map_err(|e| StateStoreError::Database(format!("verify update: {e}")))?
            .unwrap_or(false);
        // `bind_update` already wrote; the verification above confirms
        // the WHERE clause matched. If it didn't, the original update
        // was a silent no-op — surface NotFound.
        if !exists {
            return Err(StateStoreError::NotFound);
        }
        Ok(())
    }

    fn get_transfer(&self, transfer_id: TransferId) -> StateStoreResult<TransferRecord> {
        let g = lock_db(self.conn.lock())?;
        g.query_row(
            &format!("SELECT {TRANSFER_COLS_LIST} FROM transfers WHERE transfer_id=?"),
            params![transfer_id.as_bytes().as_slice()],
            row_to_record,
        )
        .optional()
        .map_err(|e| StateStoreError::Database(format!("get_transfer: {e}")))?
        .ok_or(StateStoreError::NotFound)
    }

    fn get_transfer_by_idempotency(
        &self,
        role: Role,
        idempotency_key: &str,
    ) -> StateStoreResult<TransferRecord> {
        let g = lock_db(self.conn.lock())?;
        g.query_row(
            &format!(
                "SELECT {TRANSFER_COLS_LIST} FROM transfers \
                 WHERE role=? AND idempotency_key=?"
            ),
            params![role_to_int(role), idempotency_key],
            row_to_record,
        )
        .optional()
        .map_err(|e| StateStoreError::Database(format!("get by idem: {e}")))?
        .ok_or(StateStoreError::NotFound)
    }

    fn list_transfers_by_path(
        &self,
        role: Role,
        path_prefix: &str,
    ) -> StateStoreResult<Vec<TransferRecord>> {
        let g = lock_db(self.conn.lock())?;
        let like = format!("{path_prefix}%");
        let mut stmt = g
            .prepare(&format!(
                "SELECT {TRANSFER_COLS_LIST} FROM transfers \
                 WHERE role=? AND remote_path LIKE ? \
                 ORDER BY created_ms ASC"
            ))
            .map_err(|e| StateStoreError::Database(format!("prepare list: {e}")))?;
        let rows = stmt
            .query_map(params![role_to_int(role), like], row_to_record)
            .map_err(|e| StateStoreError::Database(format!("query list: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StateStoreError::Database(format!("row: {e}")))?);
        }
        Ok(out)
    }

    fn write_bitmap(&self, transfer_id: TransferId, bitmap: &ChunkBitmap) -> StateStoreResult<()> {
        let mut g = lock_db(self.conn.lock())?;
        let tx = g
            .transaction()
            .map_err(|e| StateStoreError::Database(format!("begin tx: {e}")))?;
        tx.execute(
            "DELETE FROM chunk_bitmap WHERE transfer_id=?",
            params![transfer_id.as_bytes().as_slice()],
        )
        .map_err(|e| StateStoreError::Database(format!("delete bitmap: {e}")))?;
        {
            let mut stmt = tx
                .prepare("INSERT INTO chunk_bitmap (transfer_id, chunk_index) VALUES (?, ?)")
                .map_err(|e| StateStoreError::Database(format!("prepare insert bitmap: {e}")))?;
            for idx in bitmap.indices() {
                stmt.execute(params![transfer_id.as_bytes().as_slice(), idx as i64,])
                    .map_err(|e| StateStoreError::Database(format!("insert bitmap row: {e}")))?;
            }
        }
        tx.execute(
            "UPDATE transfers SET bytes_completed=?, updated_ms=? WHERE transfer_id=?",
            params![
                bitmap.bytes_completed() as i64,
                current_ms() as i64,
                transfer_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|e| StateStoreError::Database(format!("update bytes_completed: {e}")))?;
        tx.commit()
            .map_err(|e| StateStoreError::Database(format!("commit tx: {e}")))?;
        Ok(())
    }

    fn read_bitmap(&self, transfer_id: TransferId) -> StateStoreResult<ChunkBitmap> {
        let g = lock_db(self.conn.lock())?;
        // Verify the transfer exists; an empty bitmap for a non-existent
        // transfer would mask caller bugs.
        let exists: bool = g
            .query_row(
                "SELECT 1 FROM transfers WHERE transfer_id=?",
                params![transfer_id.as_bytes().as_slice()],
                |_r| Ok(true),
            )
            .optional()
            .map_err(|e| StateStoreError::Database(format!("read bitmap exists: {e}")))?
            .unwrap_or(false);
        if !exists {
            return Err(StateStoreError::NotFound);
        }
        let mut stmt = g
            .prepare(
                "SELECT chunk_index FROM chunk_bitmap WHERE transfer_id=? \
                 ORDER BY chunk_index",
            )
            .map_err(|e| StateStoreError::Database(format!("prepare read bitmap: {e}")))?;
        let rows = stmt
            .query_map(params![transfer_id.as_bytes().as_slice()], |r| {
                let idx: i64 = r.get(0)?;
                Ok(idx as u64)
            })
            .map_err(|e| StateStoreError::Database(format!("query read bitmap: {e}")))?;
        let mut indices: Vec<u64> = Vec::new();
        for r in rows {
            indices.push(r.map_err(|e| StateStoreError::Database(format!("row: {e}")))?);
        }
        let bytes_completed: i64 = g
            .query_row(
                "SELECT bytes_completed FROM transfers WHERE transfer_id=?",
                params![transfer_id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .map_err(|e| StateStoreError::Database(format!("read bytes_completed: {e}")))?;
        Ok(ChunkBitmap::from_sorted_indices(
            &indices,
            bytes_completed as u64,
        ))
    }

    fn delete_bitmap(&self, transfer_id: TransferId) -> StateStoreResult<()> {
        let g = lock_db(self.conn.lock())?;
        g.execute(
            "DELETE FROM chunk_bitmap WHERE transfer_id=?",
            params![transfer_id.as_bytes().as_slice()],
        )
        .map_err(|e| StateStoreError::Database(format!("delete bitmap: {e}")))?;
        Ok(())
    }

    fn write_journal(&self, entry: &CommitJournalEntry) -> StateStoreResult<()> {
        let g = lock_db(self.conn.lock())?;
        g.execute(
            "INSERT INTO commit_journal (transfer_id, file_id, remote_path, status, updated_ms) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (transfer_id, file_id) DO UPDATE SET \
                remote_path=excluded.remote_path, status=excluded.status, updated_ms=excluded.updated_ms",
            params![
                entry.transfer_id.as_bytes().as_slice(),
                entry.file_id as i64,
                entry.remote_path,
                entry.status.name(),
                entry.updated_ms as i64,
            ],
        )
        .map_err(|e| StateStoreError::Database(format!("write journal: {e}")))?;
        Ok(())
    }

    fn pending_journal(&self) -> StateStoreResult<Vec<CommitJournalEntry>> {
        let g = lock_db(self.conn.lock())?;
        let mut stmt = g
            .prepare(
                "SELECT transfer_id, file_id, remote_path, status, updated_ms \
                 FROM commit_journal WHERE status != 'committed'",
            )
            .map_err(|e| StateStoreError::Database(format!("prepare pending journal: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                let tid_blob: Vec<u8> = r.get(0)?;
                let tid = TransferId::from_bytes(&tid_blob)
                    .ok_or_else(|| rusqlite::Error::InvalidQuery)?;
                let file_id: i64 = r.get(1)?;
                let remote_path: String = r.get(2)?;
                let status: String = r.get(3)?;
                let updated_ms: i64 = r.get(4)?;
                let status =
                    CommitStatus::parse(&status).ok_or_else(|| rusqlite::Error::InvalidQuery)?;
                Ok(CommitJournalEntry {
                    transfer_id: tid,
                    file_id: file_id as u64,
                    remote_path,
                    status,
                    updated_ms: updated_ms as u64,
                })
            })
            .map_err(|e| StateStoreError::Database(format!("query pending journal: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StateStoreError::Database(format!("row: {e}")))?);
        }
        Ok(out)
    }

    fn mark_journal_committed(
        &self,
        transfer_id: TransferId,
        file_id: u64,
    ) -> StateStoreResult<()> {
        let g = lock_db(self.conn.lock())?;
        let n = g
            .execute(
                "UPDATE commit_journal SET status='committed', updated_ms=? \
                 WHERE transfer_id=? AND file_id=?",
                params![
                    current_ms() as i64,
                    transfer_id.as_bytes().as_slice(),
                    file_id as i64,
                ],
            )
            .map_err(|e| StateStoreError::Database(format!("mark committed: {e}")))?;
        if n == 0 {
            return Err(StateStoreError::NotFound);
        }
        Ok(())
    }

    fn delete_transfer(&self, transfer_id: TransferId) -> StateStoreResult<()> {
        let g = lock_db(self.conn.lock())?;
        g.execute(
            "DELETE FROM transfers WHERE transfer_id=?",
            params![transfer_id.as_bytes().as_slice()],
        )
        .map_err(|e| StateStoreError::Database(format!("delete transfer: {e}")))?;
        Ok(())
    }

    fn recover_commit_journal(&self) -> StateStoreResult<Vec<JournalRecovery>> {
        let entries = self.pending_journal()?;
        Ok(entries
            .into_iter()
            .map(|e| match e.status {
                CommitStatus::Renamed => JournalRecovery::Finalize {
                    transfer_id: e.transfer_id,
                    file_id: e.file_id,
                },
                CommitStatus::Pending => JournalRecovery::LeavePending {
                    transfer_id: e.transfer_id,
                    file_id: e.file_id,
                },
                CommitStatus::Committed => unreachable!(),
            })
            .collect())
    }

    fn mark_active_transfers_resumable(&self) -> StateStoreResult<usize> {
        let g = lock_db(self.conn.lock())?;
        let count = g
            .execute(
                "UPDATE transfers SET status='resumable', updated_ms=? WHERE status='active'",
                params![current_ms() as i64],
            )
            .map_err(|e| StateStoreError::Database(format!("mark active resumable: {e}")))?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::TransferStatus;
    use crate::util::Hash;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("velcrux-state-{pid}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn sample(idem: &str, tid: TransferId) -> TransferRecord {
        TransferRecord {
            transfer_id: tid,
            idempotency_key: idem.into(),
            role: Role::Client,
            direction: Direction::Upload,
            status: TransferStatus::Active,
            remote_path: "data/x.bin".into(),
            local_path: "/tmp/x.bin".into(),
            file_size: 10_000_000,
            file_hash: Hash::of(b"hello"),
            verified_up_to: 0,
            last_checkpoint_ms: 0,
            bytes_completed: 0,
            staging_relpath: String::new(),
            created_ms: 1_000_000,
            updated_ms: 1_000_000,
        }
    }

    #[test]
    fn new_creates_db_at_absolute_path() {
        let p = tmp_path("s.db");
        let _ = std::fs::remove_file(&p);
        let s = SqliteStateStore::new(&p).unwrap();
        assert!(p.exists(), "DB file should exist after open");
        let s2 = SqliteStateStore::new(&p).unwrap();
        assert!(s2.path().is_absolute());
    }

    #[test]
    fn new_rejects_relative_path() {
        let p = std::path::PathBuf::from("relative.db");
        let r = SqliteStateStore::new(&p);
        assert!(matches!(r, Err(StateStoreError::Database(_))));
    }

    #[test]
    fn upsert_then_get_by_id() {
        let p = tmp_path("u.db");
        let s = SqliteStateStore::new(&p).unwrap();
        let tid = TransferId::generate();
        let r = sample("k", tid);
        let outcome = s.upsert_transfer(&r).unwrap();
        assert!(matches!(outcome, UpsertOutcome::Inserted));
        let got = s.get_transfer(tid).unwrap();
        assert_eq!(got.transfer_id, tid);
        assert_eq!(got.file_size, 10_000_000);
    }

    #[test]
    fn upsert_reuses_idempotency_key() {
        let p = tmp_path("idem.db");
        let s = SqliteStateStore::new(&p).unwrap();
        let tid = TransferId::generate();
        let r = sample("k", tid);
        s.upsert_transfer(&r).unwrap();
        match s.upsert_transfer(&r).unwrap() {
            UpsertOutcome::Reused(got) => assert_eq!(got.transfer_id, tid),
            other => panic!("expected Reused, got {:?}", other),
        }
    }

    #[test]
    fn upsert_rejects_mismatched_retry() {
        let p = tmp_path("conflict.db");
        let s = SqliteStateStore::new(&p).unwrap();
        let tid = TransferId::generate();
        let mut r = sample("k", tid);
        s.upsert_transfer(&r).unwrap();
        r.file_size = 1;
        assert!(matches!(
            s.upsert_transfer(&r).unwrap_err(),
            StateStoreError::IdempotencyConflict(_)
        ));
    }

    #[test]
    fn bitmap_roundtrip_through_sqlite() {
        let p = tmp_path("bm.db");
        let s = SqliteStateStore::new(&p).unwrap();
        let tid = TransferId::generate();
        s.upsert_transfer(&sample("k", tid)).unwrap();
        let mut bm = ChunkBitmap::new();
        for i in 0u64..10 {
            bm.mark_complete(i, 4096);
        }
        s.write_bitmap(tid, &bm).unwrap();
        let read = s.read_bitmap(tid).unwrap();
        assert_eq!(read, bm);
    }

    #[test]
    fn bitmap_replace_is_whole() {
        let p = tmp_path("bmr.db");
        let s = SqliteStateStore::new(&p).unwrap();
        let tid = TransferId::generate();
        s.upsert_transfer(&sample("k", tid)).unwrap();
        let mut bm = ChunkBitmap::new();
        bm.mark_complete(0, 1);
        bm.mark_complete(1, 1);
        s.write_bitmap(tid, &bm).unwrap();
        let mut bm2 = ChunkBitmap::new();
        bm2.mark_complete(5, 1);
        s.write_bitmap(tid, &bm2).unwrap();
        let read = s.read_bitmap(tid).unwrap();
        assert!(!read.contains(0));
        assert!(!read.contains(1));
        assert!(read.contains(5));
    }

    #[test]
    fn journal_recovery_split() {
        let p = tmp_path("jr.db");
        let s = SqliteStateStore::new(&p).unwrap();
        let t1 = TransferId::generate();
        let t2 = TransferId::generate();
        let t3 = TransferId::generate();
        s.upsert_transfer(&sample("k1", t1)).unwrap();
        s.upsert_transfer(&sample("k2", t2)).unwrap();
        s.upsert_transfer(&sample("k3", t3)).unwrap();
        s.write_journal(&CommitJournalEntry {
            transfer_id: t1,
            file_id: 1,
            remote_path: "a".into(),
            status: CommitStatus::Renamed,
            updated_ms: 0,
        })
        .unwrap();
        s.write_journal(&CommitJournalEntry {
            transfer_id: t2,
            file_id: 1,
            remote_path: "b".into(),
            status: CommitStatus::Pending,
            updated_ms: 0,
        })
        .unwrap();
        s.write_journal(&CommitJournalEntry {
            transfer_id: t3,
            file_id: 1,
            remote_path: "c".into(),
            status: CommitStatus::Committed,
            updated_ms: 0,
        })
        .unwrap();
        let rec = s.recover_commit_journal().unwrap();
        assert_eq!(rec.len(), 2);
        assert!(rec.iter().any(
            |r| matches!(r, JournalRecovery::Finalize { transfer_id, .. } if *transfer_id == t1)
        ));
        assert!(rec.iter().any(
            |r| matches!(r, JournalRecovery::LeavePending { transfer_id, .. } if *transfer_id == t2)
        ));
    }

    #[test]
    fn delete_cascades_to_bitmap_and_journal() {
        let p = tmp_path("del.db");
        let s = SqliteStateStore::new(&p).unwrap();
        let tid = TransferId::generate();
        s.upsert_transfer(&sample("k", tid)).unwrap();
        let mut bm = ChunkBitmap::new();
        bm.mark_complete(0, 1);
        s.write_bitmap(tid, &bm).unwrap();
        s.write_journal(&CommitJournalEntry {
            transfer_id: tid,
            file_id: 1,
            remote_path: "x".into(),
            status: CommitStatus::Pending,
            updated_ms: 0,
        })
        .unwrap();
        s.delete_transfer(tid).unwrap();
        assert!(s.get_transfer(tid).is_err());
        assert!(s.read_bitmap(tid).is_err());
        assert!(s.pending_journal().unwrap().is_empty());
    }

    #[test]
    fn list_by_path_filters_and_orders() {
        let p = tmp_path("list.db");
        let s = SqliteStateStore::new(&p).unwrap();
        for (idem, path, ms) in [
            ("a", "data/a.bin", 10u64),
            ("b", "data/b.bin", 20),
            ("c", "other/c.bin", 5),
        ] {
            let mut r = sample(idem, TransferId::generate());
            r.remote_path = path.into();
            r.created_ms = ms;
            s.upsert_transfer(&r).unwrap();
        }
        let got = s.list_transfers_by_path(Role::Client, "data/").unwrap();
        assert_eq!(got.len(), 2);
        assert!(got[0].created_ms <= got[1].created_ms);
    }

    #[test]
    fn state_survives_drop_and_reopen() {
        let p = tmp_path("persist.db");
        let tid = TransferId::generate();
        {
            let s = SqliteStateStore::new(&p).unwrap();
            s.upsert_transfer(&sample("k", tid)).unwrap();
            let mut bm = ChunkBitmap::new();
            bm.mark_complete(7, 4096);
            s.write_bitmap(tid, &bm).unwrap();
        }
        let s2 = SqliteStateStore::new(&p).unwrap();
        let r = s2.get_transfer(tid).unwrap();
        assert_eq!(r.transfer_id, tid);
        let bm = s2.read_bitmap(tid).unwrap();
        assert!(bm.contains(7));
        assert_eq!(bm.bytes_completed(), 4096);
    }
}
