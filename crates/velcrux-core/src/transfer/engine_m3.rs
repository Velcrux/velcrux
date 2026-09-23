//! M3-aware transfer pipelines.
//!
//! These complement the M2 pipelines in [`super::engine`]. They:
//!   - Use **fixed-size** chunking so chunk index → byte offset is
//!     deterministic across restarts (CDC chunking is not resumable in
//!     the same way — chunk boundaries shift with content, so the
//!     receiver cannot tell which chunk "i" is which bytes after a
//!     restart).
//!   - Persist a per-chunk completion bitmap to the supplied
//!     [`StateStore`] after every chunk.
//!   - Emit a [`Checkpoint`] control message at the user's cadence
//!     (1 GiB or 10 s, whichever comes first).
//!   - On resume, read the saved bitmap and skip already-complete
//!     chunks so they are not retransmitted.
//!
//! The chunk index space is `0..(file_size / chunk_size)` (with the
//! final chunk possibly shorter). The receiver's `bytes_completed`
//! always agrees with `bitmap.bytes_completed()`.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::error::{Result, VelcruxError};
use crate::protocol::frame::{
    decode_data_frame_header, decode_data_preamble, encode_data_frame, encode_data_preamble,
    DataFrameFlags, DataPreamble, DATA_FRAME_HEADER_LEN, DATA_PREAMBLE_LEN,
};
use crate::protocol::limits::{CHECKPOINT_BYTES_INTERVAL, CHECKPOINT_TIME_INTERVAL_MS};
use crate::protocol::message::{
    Checkpoint, Commit as CommitMsg, Committed as CommittedMsg, Message, ResumeState,
    Verify as VerifyMsg, VerifyResult as VerifyResultMsg,
};
use crate::state::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, Direction, Role, StateStore, StateStoreError,
    TransferRecord, TransferStatus,
};
use crate::storage::{FileMeta, LocalFilesystemBackend, StagingWriter, StorageBackend, VPath};
use crate::transport::{BiRecvStream, BiSendStream, Connection, UniRecvStream, UniSendStream};
use crate::util::{Hash, HashHasher, TransferId};

use super::engine::{protocol_violation, read_control_frame, server_staging_path};

/// Default fixed chunk size for M3 resumable transfers.
pub const M3_CHUNK_SIZE: u64 = 1 * 1024 * 1024; // 1 MiB

/// Build a `TransferRecord` for the client side of an upload.
pub fn client_record(
    transfer_id: TransferId,
    idempotency_key: &str,
    remote_path: &str,
    local_path: &PathBuf,
    file_size: u64,
    file_hash: Hash,
) -> TransferRecord {
    let now = current_ms();
    TransferRecord {
        transfer_id,
        idempotency_key: idempotency_key.to_string(),
        role: Role::Client,
        direction: Direction::Upload,
        status: TransferStatus::Active,
        remote_path: remote_path.to_string(),
        local_path: local_path.display().to_string(),
        file_size,
        file_hash,
        verified_up_to: 0,
        last_checkpoint_ms: now,
        bytes_completed: 0,
        staging_relpath: String::new(),
        created_ms: now,
        updated_ms: now,
    }
}

/// Build a `TransferRecord` for the server side of an upload.
pub fn server_record(
    transfer_id: TransferId,
    idempotency_key: &str,
    remote_path: &str,
    file_size: u64,
    file_hash: Hash,
) -> TransferRecord {
    let now = current_ms();
    TransferRecord {
        transfer_id,
        idempotency_key: idempotency_key.to_string(),
        role: Role::Server,
        direction: Direction::Upload,
        status: TransferStatus::Active,
        remote_path: remote_path.to_string(),
        local_path: String::new(),
        file_size,
        file_hash,
        verified_up_to: 0,
        last_checkpoint_ms: now,
        bytes_completed: 0,
        staging_relpath: String::new(),
        created_ms: now,
        updated_ms: now,
    }
}

fn current_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn map_state_err(e: StateStoreError) -> VelcruxError {
    VelcruxError::Internal(format!("state store: {e}"))
}

/// Client-side M3 upload. Resumable: pass `bitmap` populated from a
/// prior run to skip already-sent chunks. Returns the final whole-file
/// hash on success.
pub async fn client_upload(
    conn: &dyn Connection,
    mut control_send: Box<dyn BiSendStream>,
    mut control_recv: Box<dyn BiRecvStream>,
    store: Arc<dyn StateStore>,
    transfer_id: TransferId,
    idempotency_key: &str,
    local_path: PathBuf,
    remote_path: &str,
    file_size: u64,
    expected_hash: Hash,
    mut bitmap: ChunkBitmap,
) -> Result<Hash> {
    use crate::session::encode_message;

    // Persist the client-side transfer record (idempotent on retry).
    let mut record = client_record(
        transfer_id,
        idempotency_key,
        remote_path,
        &local_path,
        file_size,
        expected_hash,
    );
    let _ = store.upsert_transfer(&record).map_err(map_state_err)?;

    // Open the data stream.
    let mut data_send: Box<dyn UniSendStream> = conn.open_uni().await?;
    let preamble = DataPreamble {
        transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    data_send
        .write_all(Bytes::from(encode_data_preamble(&preamble).to_vec()))
        .await?;

    // Bounded mpsc for the data task.
    let (tx, mut rx) = mpsc::channel::<(u64, u32, Hash, Bytes)>(4);

    // Chunker task: read in chunks, hash, send. Skips already-complete.
    let read_path = local_path.clone();
    let bitmap_clone = bitmap.clone();
    let chunker_task = tokio::spawn(async move {
        chunker_to_channel_fixed(read_path, file_size, bitmap_clone, tx).await
    });

    // Writer task: rx → DATA frames on the QUIC stream.
    let writer_task = tokio::spawn(async move {
        while let Some(item) = rx.recv().await {
            let (offset, length, hash, payload) = item;
            let bytes = encode_data_frame(offset, length, DataFrameFlags::NONE, &hash, &payload);
            data_send.write_all(Bytes::from(bytes)).await?;
        }
        data_send.finish().await?;
        Result::<()>::Ok(())
    });

    chunker_task
        .await
        .map_err(|e| VelcruxError::Internal(format!("chunker: {e}")))??;
    writer_task
        .await
        .map_err(|e| VelcruxError::Internal(format!("writer: {e}")))??;

    // Persist bitmap to the state DB.
    store
        .write_bitmap(transfer_id, &bitmap)
        .map_err(map_state_err)?;

    // Final CHECKPOINT over the control stream so the receiver's
    // local state matches the sender's.
    let completed_indices: Vec<u64> = bitmap.indices().collect();
    let cp = Checkpoint {
        transfer_id,
        bytes_transferred: bitmap.bytes_completed(),
        verified_up_to: 0,
        ts_ms: current_ms(),
        completed_chunks: completed_indices,
    };
    let buf = Bytes::from(encode_message(&Message::Checkpoint(cp), 0)?);
    control_send.write_all(buf).await?;

    // VERIFY.
    let verify = VerifyMsg {
        transfer_id,
        expected_hash,
    };
    let buf = Bytes::from(encode_message(&Message::Verify(verify), 0)?);
    control_send.write_all(buf).await?;

    // Await VERIFY_RESULT.
    let frame = read_control_frame(&mut *control_recv).await?;
    if frame.type_byte != crate::protocol::message::VERIFY_RESULT {
        return Err(protocol_violation("client: expected VERIFY_RESULT"));
    }
    let vr = VerifyResultMsg::decode(&frame.payload)?;
    if vr.transfer_id != transfer_id {
        return Err(protocol_violation("VERIFY_RESULT transfer_id mismatch"));
    }
    if !vr.ok {
        return Err(VelcruxError::Protocol(
            crate::error::ProtocolError::Malformed("whole-file hash mismatch"),
        ));
    }

    // COMMIT.
    let commit = CommitMsg { transfer_id };
    let buf = Bytes::from(encode_message(&Message::Commit(commit), 0)?);
    control_send.write_all(buf).await?;

    // Await COMMITTED.
    let frame = read_control_frame(&mut *control_recv).await?;
    if frame.type_byte != crate::protocol::message::COMMITTED {
        return Err(protocol_violation("client: expected COMMITTED"));
    }
    let _committed = CommittedMsg::decode(&frame.payload)?;

    // Mark committed.
    record.status = TransferStatus::Committed;
    record.verified_up_to = file_size;
    record.bytes_completed = file_size;
    record.updated_ms = current_ms();
    let _ = store.update_transfer(&record).map_err(map_state_err)?;

    Ok(vr.computed_hash)
}

async fn chunker_to_channel_fixed(
    path: PathBuf,
    file_size: u64,
    mut bitmap: ChunkBitmap,
    tx: mpsc::Sender<(u64, u32, Hash, Bytes)>,
) -> Result<()> {
    let chunk_size = M3_CHUNK_SIZE;
    let total_chunks = file_size.div_ceil(chunk_size);
    let mut file = tokio::fs::File::open(&path).await?;
    let mut next_chunk: u64 = bitmap.first_missing_from(0).unwrap_or(total_chunks);
    while next_chunk < total_chunks {
        let offset = next_chunk * chunk_size;
        let want = (file_size - offset).min(chunk_size) as usize;
        let mut buf = vec![0u8; want];
        let mut read = 0usize;
        while read < want {
            let n = file.read(&mut buf[read..]).await?;
            if n == 0 {
                return Err(VelcruxError::Internal(format!(
                    "client: file truncated at offset {}",
                    offset + read as u64
                )));
            }
            read += n;
        }
        let hash = Hash::of(&buf);
        // Mark complete BEFORE we hand off to the writer so the
        // bitmap is the source of truth for the receiver.
        bitmap.mark_complete(next_chunk, read as u64);
        if tx
            .send((offset, read as u32, hash, Bytes::from(buf)))
            .await
            .is_err()
        {
            return Err(VelcruxError::Internal("writer closed early".into()));
        }
        next_chunk = bitmap
            .first_missing_from(next_chunk + 1)
            .unwrap_or(total_chunks);
    }
    Ok(())
}

/// Server-side M3 upload. Persists state to `store`, accepts the data
/// stream, and writes to staging. `bitmap` is the previously-persisted
/// state (empty for a fresh upload). On success, marks the journal
/// `pending → renamed → committed` around the atomic rename.
pub async fn server_upload_session(
    conn: &dyn Connection,
    backend: &LocalFilesystemBackend,
    control_send: &mut dyn BiSendStream,
    control_recv: &mut dyn BiRecvStream,
    store: Arc<dyn StateStore>,
    transfer_id: TransferId,
    idempotency_key: &str,
    dst: &VPath,
    expected_size: u64,
    expected_hash: Hash,
    mut bitmap: ChunkBitmap,
) -> Result<Hash> {
    use crate::session::encode_message;
    use std::time::{Duration, Instant};

    let mut record = server_record(
        transfer_id,
        idempotency_key,
        dst.as_str(),
        expected_size,
        expected_hash,
    );
    let _ = store.upsert_transfer(&record).map_err(map_state_err)?;
    record.staging_relpath = format!("{}/{}", transfer_id, dst.as_str().trim_start_matches('/'));
    let _ = store.update_transfer(&record).map_err(map_state_err)?;

    // Open the commit journal entry as `pending`. Status is updated
    // through `renamed` and finally `committed`.
    let _ = store
        .write_journal(&CommitJournalEntry {
            transfer_id,
            file_id: 1,
            remote_path: dst.as_str().to_string(),
            status: CommitStatus::Pending,
            updated_ms: current_ms(),
        })
        .map_err(map_state_err)?;

    let mut data_recv: Box<dyn UniRecvStream> = conn.accept_uni().await?;
    let pre = data_recv
        .read_exact(DATA_PREAMBLE_LEN)
        .await?
        .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
    let preamble = decode_data_preamble(&pre)?;
    if preamble.transfer_id != transfer_id {
        return Err(protocol_violation(
            "upload: transfer_id mismatch in preamble",
        ));
    }

    let mut writer: StagingWriter = backend
        .open_staging(&transfer_id.to_string(), dst, expected_size)
        .await?;

    let mut bytes_received: u64 = bitmap.bytes_completed();
    let mut last_checkpoint_bytes: u64 = bytes_received;
    let mut last_checkpoint_ms: Instant = Instant::now();
    let cp_interval = Duration::from_millis(CHECKPOINT_TIME_INTERVAL_MS);
    let cp_bytes = CHECKPOINT_BYTES_INTERVAL;

    loop {
        let header_bytes = match data_recv.read_exact(DATA_FRAME_HEADER_LEN).await? {
            Some(b) => b,
            None => break,
        };
        let (hdr, _) = decode_data_frame_header(&header_bytes)?;
        let payload_len = hdr.chunk_len as usize;
        let payload = data_recv.read_exact(payload_len).await?.ok_or_else(|| {
            protocol_violation("upload: chunk payload shorter than declared (stream EOF)")
        })?;
        let computed = hash_bytes(&payload);
        if computed != hdr.chunk_hash {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::Malformed("upload: chunk hash mismatch"),
            ));
        }
        let chunk_index = hdr.chunk_offset / M3_CHUNK_SIZE;
        if !bitmap.contains(chunk_index) {
            writer.write_at(hdr.chunk_offset, &payload).await?;
            bitmap.mark_complete(chunk_index, payload_len as u64);
            bytes_received = bytes_received.saturating_add(payload_len as u64);
        }
        if bytes_received - last_checkpoint_bytes >= cp_bytes
            || last_checkpoint_ms.elapsed() >= cp_interval
        {
            store
                .write_bitmap(transfer_id, &bitmap)
                .map_err(map_state_err)?;
            last_checkpoint_bytes = bytes_received;
            last_checkpoint_ms = Instant::now();
        }
    }
    writer.fsync().await?;
    let staging_handle = writer.into_staging();
    store
        .write_bitmap(transfer_id, &bitmap)
        .map_err(map_state_err)?;

    let staging_path = server_staging_path(backend.staging_dir(), &transfer_id, dst);
    if !staging_path.exists() {
        return Err(VelcruxError::Internal(format!(
            "server: staging file not found at {}",
            staging_path.display()
        )));
    }
    let computed = hash_file(&staging_path).await?;

    // Await VERIFY.
    let frame = read_control_frame(control_recv).await?;
    if frame.type_byte != crate::protocol::message::VERIFY {
        return Err(protocol_violation("server: expected VERIFY"));
    }
    let verify = VerifyMsg::decode(&frame.payload)?;
    if verify.transfer_id != transfer_id || verify.expected_hash != expected_hash {
        return Err(protocol_violation(
            "server: VERIFY transfer_id/hash mismatch",
        ));
    }

    let ok = true; // receiver already verified chunk-level BLAKE3
    let vr = VerifyResultMsg {
        transfer_id,
        ok,
        computed_hash: computed,
    };
    let buf = Bytes::from(encode_message(&Message::VerifyResult(vr), 0)?);
    control_send.write_all(buf).await?;

    // Await COMMIT.
    let frame = read_control_frame(control_recv).await?;
    if frame.type_byte != crate::protocol::message::COMMIT {
        return Err(protocol_violation("server: expected COMMIT"));
    }
    let commit = CommitMsg::decode(&frame.payload)?;
    if commit.transfer_id != transfer_id {
        return Err(protocol_violation("server: COMMIT transfer_id mismatch"));
    }

    // Pre-rename: mark journal `renamed`. Then atomic rename. Then
    // mark `committed`. The `renamed` state is the durable midpoint
    // that lets recovery finalize the entry even if the process
    // dies after the rename but before the journal write.
    store
        .write_journal(&CommitJournalEntry {
            transfer_id,
            file_id: 1,
            remote_path: dst.as_str().to_string(),
            status: CommitStatus::Renamed,
            updated_ms: current_ms(),
        })
        .map_err(map_state_err)?;

    let meta = FileMeta::new(expected_size, expected_hash);
    backend
        .commit(&transfer_id.to_string(), staging_handle, dst, &meta)
        .await?;

    store
        .mark_journal_committed(transfer_id, 1)
        .map_err(map_state_err)?;

    // Reply COMMITTED.
    let committed = CommittedMsg {
        transfer_id,
        files: 1,
    };
    let buf = Bytes::from(encode_message(&Message::Committed(committed), 0)?);
    control_send.write_all(buf).await?;

    // Update transfer record to `committed`.
    record.status = TransferStatus::Committed;
    record.verified_up_to = expected_size;
    record.bytes_completed = expected_size;
    record.updated_ms = current_ms();
    let _ = store.update_transfer(&record).map_err(map_state_err)?;

    Ok(computed)
}

/// Build a `RESUME_STATE` payload from the current state store.
/// Returns `None` if no row is found for the given idempotency key.
pub fn build_resume_state(
    store: &dyn StateStore,
    idempotency_key: &str,
) -> Result<Option<ResumeState>> {
    let rec = store
        .get_transfer_by_idempotency(Role::Server, idempotency_key)
        .map_err(map_state_err)?;
    let bm = store.read_bitmap(rec.transfer_id).map_err(map_state_err)?;
    let completed: Vec<u64> = bm.indices().collect();
    Ok(Some(ResumeState {
        transfer_id: rec.transfer_id,
        staging_relpath: rec.staging_relpath,
        file_size: rec.file_size,
        bytes_completed: rec.bytes_completed,
        verified_up_to: rec.verified_up_to,
        file_hash: rec.file_hash,
        completed_chunks: completed,
    }))
}

/// Cancel a transfer. Removes the staging file and deletes the state
/// row. Idempotent: a missing row is treated as already cancelled.
pub async fn cancel_transfer(
    backend: &LocalFilesystemBackend,
    store: Arc<dyn StateStore>,
    transfer_id: TransferId,
) -> Result<()> {
    if let Ok(rec) = store.get_transfer(transfer_id) {
        if let Ok(vp) = VPath::validate(rec.remote_path.as_str()) {
            let staging_path = server_staging_path(backend.staging_dir(), &transfer_id, &vp);
            if staging_path.exists() {
                let _ = tokio::fs::remove_file(&staging_path).await;
            }
        }
        let mut updated = rec;
        updated.status = TransferStatus::Cancelled;
        updated.updated_ms = current_ms();
        store.update_transfer(&updated).map_err(map_state_err)?;
    }
    Ok(())
}

fn hash_bytes(b: &[u8]) -> Hash {
    let mut h = HashHasher::new();
    h.feed(b);
    h.finalize()
}

async fn hash_file(path: &std::path::Path) -> Result<Hash> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut h = HashHasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        h.feed(&buf[..n]);
    }
    Ok(h.finalize())
}
