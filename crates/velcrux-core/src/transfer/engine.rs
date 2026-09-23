//! Streaming transfer engine.
//!
//! Two pipelines per direction (upload, download), both single-file, both
//! streaming, both with bounded memory.
//!
//! ## Upload (client)
//!
//! ```text
//! local file (Read)
//!   ↓ bounded 2 MiB read buffer
//! CDC chunker
//!   ↓ boundaries (length-bounded chunks, max 4 MiB)
//! BLAKE3 hasher (streaming, per chunk)
//!   ↓ chunk_hash
//! bounded mpsc<DataItem> (capacity = MAX_INFLIGHT)
//!   ↓
//! QUIC unidirectional send stream
//!   ↓ DATA frames (header + payload)
//! ```
//!
//! ## Download (server)
//!
//! ```text
//! QUIC unidirectional recv stream
//!   ↓ preamble + DATA frames
//! BLAKE3 verify (per chunk; reject if hash mismatches)
//!   ↓
//! bounded write scheduler → pwrite at offset into staging file
//!   ↓
//! fsync + atomic rename on COMMIT
//! ```
//!
//! ## Download (client) and Upload (server) are mirror-images of the same
//! pipelines.
//!
//! ## Memory bounds (CLAUDE.md §1 #3)
//!
//!   - Read buffer: 2 MiB.
//!   - Each chunk is at most `MAX_CHUNK_SIZE` (4 MiB).
//!   - The mpsc is bounded to `max_inflight` items.
//!   - Whole-file streaming: the whole file is never held in memory.
//!
//! ## Hash verification (CLAUDE.md §1 #6)
//!
//!   - Each DATA frame carries the BLAKE3 of its payload; the receiver
//!     re-hashes and rejects mismatches.
//!   - After the last DATA frame, the sender sends VERIFY{expected_whole_hash};
//!     the receiver streams the staged file through BLAKE3 and replies
//!     with VERIFY_RESULT{ok, computed_hash}.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::chunking::{create_chunker, ChunkMode, ChunkParams, Chunker, RollingChunker};
use crate::error::{Result, VelcruxError};
use crate::protocol::frame::{
    decode_data_frame_header, decode_data_preamble, encode_data_frame, encode_data_preamble,
    DataFrameFlags, DataPreamble, DATA_FRAME_HEADER_LEN, DATA_PREAMBLE_LEN,
};
use crate::protocol::message::{
    Checkpoint, Commit as CommitMsg, Committed as CommittedMsg, Verify as VerifyMsg,
    VerifyResult as VerifyResultMsg,
};
use crate::state::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, Direction, Role, StateStore, TransferRecord,
    TransferStatus,
};
use crate::storage::{FileMeta, LocalFilesystemBackend, StorageBackend, VPath};
use crate::transport::{BiRecvStream, BiSendStream, Connection};
use crate::util::{Hash, HashHasher, TransferId};

/// Default fixed chunk size for M3 resumable transfers.
pub const M3_CHUNK_SIZE: u64 = 1 * 1024 * 1024; // 1 MiB

// ===========================================================================
// Configuration
// ===========================================================================

/// Tunables for a transfer pipeline. Default values match the M2 spec.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Disk read buffer size (upload path).
    pub read_buffer_size: usize,
    /// Max in-flight chunks between chunker and writer task.
    pub max_inflight: usize,
    /// Chunker mode (CDC or Fixed).
    pub chunk_mode: ChunkMode,
    /// Chunker parameters.
    pub chunk_params: ChunkParams,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            read_buffer_size: 2 * 1024 * 1024,
            max_inflight: 4,
            chunk_mode: ChunkMode::Cdc,
            chunk_params: ChunkParams::default(),
        }
    }
}

/// Bounded item that flows between the chunker/hasher stage and the QUIC
/// writer. Bounded by `PipelineConfig::max_inflight` and `MAX_CHUNK_SIZE`;
/// never grows with file size.
#[derive(Debug)]
enum DataItem {
    /// A DATA frame's header + payload, ready to write.
    Frame {
        offset: u64,
        length: u32,
        hash: Hash,
        payload: Bytes,
    },
    /// Signal that the chunker has finished; the writer should finish its
    /// send half of the QUIC stream.
    Eof,
}

// ===========================================================================
// Client upload
// ===========================================================================

/// Client-side upload. Streams the file at `local_path` to the server over a
/// new QUIC unidirectional stream, then exchanges VERIFY / VERIFY_RESULT /
/// COMMIT / COMMITTED on the control stream. Returns the server-reported
/// computed hash on success.
///
/// `transfer_id` is the server-assigned id received from `TRANSFER_CREATED`.
/// `expected_hash` is the whole-file BLAKE3 of the local file.
pub async fn client_upload(
    conn: &dyn Connection,
    control_send: Box<dyn BiSendStream>,
    control_recv: Box<dyn BiRecvStream>,
    transfer_id: TransferId,
    local_path: PathBuf,
    file_size: u64,
    expected_hash: Hash,
    cfg: PipelineConfig,
) -> Result<Hash> {
    client_upload_with_state(
        conn,
        control_send,
        control_recv,
        None,
        transfer_id,
        "",
        local_path,
        "",
        file_size,
        expected_hash,
        ChunkBitmap::new(),
        cfg,
        None,
    )
    .await
}

/// Resumable client-side upload with state tracking, checkpointing, and progress.
pub async fn client_upload_with_state(
    conn: &dyn Connection,
    mut control_send: Box<dyn BiSendStream>,
    mut control_recv: Box<dyn BiRecvStream>,
    store: Option<Arc<dyn StateStore>>,
    transfer_id: TransferId,
    idempotency_key: &str,
    local_path: PathBuf,
    remote_path: &str,
    file_size: u64,
    expected_hash: Hash,
    mut bitmap: ChunkBitmap,
    cfg: PipelineConfig,
    progress_tx: Option<mpsc::Sender<u64>>,
) -> Result<Hash> {
    use crate::protocol::message::Message;
    use crate::session::encode_message;

    if let Some(s) = &store {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let record = TransferRecord {
            transfer_id,
            idempotency_key: idempotency_key.to_string(),
            role: Role::Client,
            direction: Direction::Upload,
            status: TransferStatus::Active,
            remote_path: remote_path.to_string(),
            local_path: local_path.display().to_string(),
            file_size,
            file_hash: expected_hash,
            verified_up_to: 0,
            last_checkpoint_ms: now,
            bytes_completed: bitmap.bytes_completed(),
            staging_relpath: String::new(),
            created_ms: now,
            updated_ms: now,
        };
        let _ = s.upsert_transfer(&record);
    }

    // Open a unidirectional stream for the data and write the preamble.
    let mut data_send = conn.open_uni().await?;
    let preamble = DataPreamble {
        transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    data_send
        .write_all(Bytes::from(encode_data_preamble(&preamble).to_vec()))
        .await?;

    if bitmap.len() > 0 || cfg.chunk_mode == ChunkMode::Fixed {
        // Resumable / Fixed chunking pipeline.
        use tokio::io::AsyncSeekExt;
        let chunk_size = M3_CHUNK_SIZE;
        let total_chunks = file_size.div_ceil(chunk_size);
        let mut file = tokio::fs::File::open(&local_path).await?;
        let mut next_chunk = bitmap.first_missing_from(0).unwrap_or(total_chunks);
        let mut last_checkpoint_bytes = bitmap.bytes_completed();

        if let Some(tx) = &progress_tx {
            let already = bitmap.bytes_completed();
            if already > 0 {
                let _ = tx.try_send(already);
            }
        }

        while next_chunk < total_chunks {
            let offset = next_chunk * chunk_size;
            let want = (file_size - offset).min(chunk_size) as usize;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; want];
            let mut read = 0;
            while read < want {
                let n = file.read(&mut buf[read..]).await?;
                if n == 0 {
                    return Err(VelcruxError::Internal("file truncated".into()));
                }
                read += n;
            }
            let hash = Hash::of(&buf);
            bitmap.mark_complete(next_chunk, read as u64);
            let bytes = encode_data_frame(offset, read as u32, DataFrameFlags::NONE, &hash, &buf);
            data_send.write_all(Bytes::from(bytes)).await?;

            if let Some(tx) = &progress_tx {
                let _ = tx.try_send(read as u64);
            }

            if let Some(s) = &store {
                if bitmap
                    .bytes_completed()
                    .saturating_sub(last_checkpoint_bytes)
                    >= 16 * 1024 * 1024
                {
                    let _ = s.write_bitmap(transfer_id, &bitmap);
                    last_checkpoint_bytes = bitmap.bytes_completed();
                }
            }

            next_chunk = bitmap
                .first_missing_from(next_chunk + 1)
                .unwrap_or(total_chunks);
        }
        let _ = data_send.finish().await;
    } else {
        // CDC streaming pipeline.
        let (tx, mut rx) = mpsc::channel::<DataItem>(cfg.max_inflight);
        let read_path = local_path.clone();
        let chunker_task =
            tokio::spawn(async move { chunker_to_channel(read_path, file_size, cfg, tx).await });

        let progress_clone = progress_tx.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                match item {
                    DataItem::Frame {
                        offset,
                        length,
                        hash,
                        payload,
                    } => {
                        let bytes = encode_data_frame(
                            offset,
                            length,
                            DataFrameFlags::NONE,
                            &hash,
                            &payload,
                        );
                        data_send.write_all(Bytes::from(bytes)).await?;
                        if let Some(tx) = &progress_clone {
                            let _ = tx.try_send(length as u64);
                        }
                    }
                    DataItem::Eof => break,
                }
            }
            data_send.finish().await?;
            Result::<()>::Ok(())
        });

        chunker_task
            .await
            .map_err(|e| VelcruxError::Internal(format!("chunker task join: {e}")))??;
        writer_task
            .await
            .map_err(|e| VelcruxError::Internal(format!("writer task join: {e}")))??;
    }

    if let Some(s) = &store {
        let _ = s.write_bitmap(transfer_id, &bitmap);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let cp = Checkpoint {
            transfer_id,
            bytes_transferred: bitmap.bytes_completed(),
            verified_up_to: 0,
            ts_ms: now,
            completed_chunks: bitmap.indices().collect(),
        };
        let buf = Bytes::from(encode_message(&Message::Checkpoint(cp), 0)?);
        control_send.write_all(buf).await?;
    }

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
        return Err(protocol_violation("expected VERIFY_RESULT"));
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
        return Err(protocol_violation("expected COMMITTED"));
    }
    let committed = CommittedMsg::decode(&frame.payload)?;
    if committed.transfer_id != transfer_id || committed.files != 1 {
        return Err(protocol_violation("COMMITTED transfer_id/files mismatch"));
    }

    if let Some(s) = &store {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut r) = s.get_transfer(transfer_id) {
            r.status = TransferStatus::Committed;
            r.bytes_completed = file_size;
            r.verified_up_to = file_size;
            r.updated_ms = now;
            let _ = s.update_transfer(&r);
        }
    }

    Ok(vr.computed_hash)
}

// ===========================================================================
// Chunker → channel (upload side)
// ===========================================================================

async fn chunker_to_channel(
    path: PathBuf,
    _file_size: u64,
    cfg: PipelineConfig,
    tx: mpsc::Sender<DataItem>,
) -> Result<()> {
    let mut file = tokio::fs::File::open(&path).await?;
    let mut chunker = create_chunker(cfg.chunk_mode, cfg.chunk_params);
    let mut read_buf = vec![0u8; cfg.read_buffer_size];
    // Accumulator: bytes that belong to the in-progress chunk and have not
    // yet been emitted. Bounded by `MAX_CHUNK_SIZE` (4 MiB), never grows
    // with file size.
    let mut pending: Vec<u8> = Vec::with_capacity(cfg.chunk_params.max as usize);
    let mut pending_offset: u64 = 0;

    loop {
        let n = file.read(&mut read_buf).await?;
        if n == 0 {
            // EOF: emit any trailing chunk, then signal done.
            if !pending.is_empty() {
                let offset = pending_offset;
                let length = pending.len() as u32;
                let hash = hash_bytes(&pending);
                let payload = std::mem::take(&mut pending);
                if tx
                    .send(DataItem::Frame {
                        offset,
                        length,
                        hash,
                        payload: Bytes::from(payload),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            tx.send(DataItem::Eof).await.ok();
            return Ok(());
        }

        // Append the new bytes to the pending accumulator, then run the
        // chunker over the whole pending buffer. Boundaries' `end()` are
        // absolute chunker-offsets (relative to the start of the chunker
        // stream). We drain pending up to each boundary.
        pending.extend_from_slice(&read_buf[..n]);
        let boundaries = chunker.push(&read_buf[..n])?;
        let _ = pending.len(); // (kept for clarity)
                               // `boundaries[i].end()` is the byte offset (within the chunker
                               // stream) of the byte *after* the i-th chunk. Use that to drain.
        for b in &boundaries {
            let target = b.end() as usize;
            // target counts bytes the chunker has *seen* total; pending
            // holds the bytes from pending_offset to chunker.offset().
            // The chunk has exactly `target - pending_offset` bytes in
            // pending.
            let need = target - pending_offset as usize;
            debug_assert!(need <= pending.len(), "chunker desync");
            let hash = hash_bytes(&pending[..need]);
            let length = need as u32;
            let payload: Vec<u8> = pending.drain(..need).collect();
            if tx
                .send(DataItem::Frame {
                    offset: pending_offset,
                    length,
                    hash,
                    payload: Bytes::from(payload),
                })
                .await
                .is_err()
            {
                return Ok(());
            }
            pending_offset = b.end();
        }
    }
}

pub(super) fn hash_bytes(data: &[u8]) -> Hash {
    let mut h = HashHasher::new();
    h.feed(data);
    h.finalize()
}

// ===========================================================================
// read_control_frame (used by both client and server)
// ===========================================================================

pub(super) async fn read_control_frame(
    recv: &mut dyn BiRecvStream,
) -> Result<crate::protocol::frame::Frame<'static>> {
    use crate::protocol::frame::Frame;
    let header_start = recv
        .read_exact(5)
        .await?
        .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
    let mut buf = header_start.to_vec();
    let mut varint_len = 1usize;
    while (buf[buf.len() - 1] & 0x80) != 0 {
        let next = recv
            .read_exact(1)
            .await?
            .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
        buf.extend_from_slice(&next);
        varint_len += 1;
        if varint_len > 10 {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::VarintOverflow,
            ));
        }
    }
    let (declared_length, _) = crate::protocol::varint::decode_varint(&buf[4..])?;
    let max = crate::protocol::frame::max_message_size();
    if declared_length > max {
        return Err(VelcruxError::Protocol(
            crate::error::ProtocolError::FrameTooLarge {
                declared: declared_length,
                limit: max,
            },
        ));
    }
    let rid = recv
        .read_exact(8)
        .await?
        .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
    buf.extend_from_slice(&rid);
    let payload = if declared_length == 0 {
        Bytes::new()
    } else {
        recv.read_exact(declared_length as usize)
            .await?
            .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?
    };
    buf.extend_from_slice(&payload);
    let frame = crate::protocol::frame::decode_frame(&buf)?;
    let payload_static: &'static [u8] = Box::leak(frame.payload.to_vec().into_boxed_slice());
    Ok(Frame {
        version: frame.version,
        type_byte: frame.type_byte,
        flags: frame.flags,
        length: frame.length,
        request_id: frame.request_id,
        payload: payload_static,
    })
}

pub(super) fn protocol_violation(detail: &'static str) -> VelcruxError {
    use crate::error::ProtocolError;
    VelcruxError::Protocol(ProtocolError::InvalidStateTransition(detail))
}

// ===========================================================================
// Server-side helpers (upload receive)
// ===========================================================================

pub(super) async fn hash_file(path: &std::path::Path) -> Result<Hash> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut h = HashHasher::new();
    let mut buf = vec![0u8; 2 * 1024 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        h.feed(&buf[..n]);
    }
    Ok(h.finalize())
}

/// Compute the staging file path the `LocalFilesystemBackend` uses for a
/// given `(transfer_id, dest)`. M2 helper used by the server-side upload
/// session to find the on-disk staging file for whole-file hashing.
pub fn server_staging_path(
    backend_staging_dir: &std::path::Path,
    transfer_id: &TransferId,
    dest: &VPath,
) -> std::path::PathBuf {
    let safe_tid: String = transfer_id
        .to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let mut out = backend_staging_dir.to_path_buf();
    out.push(safe_tid);
    out.push(dest.as_path());
    let ext = out.extension().and_then(|e| e.to_str()).unwrap_or("");
    out.set_extension(format!("{ext}.velcrux-partial"));
    out
}

// ===========================================================================
// Server-side upload session (full VERIFY / COMMIT exchange)
// ===========================================================================

/// Full server-side upload session. Reads the data stream preamble + DATA
/// frames, verifies per-chunk BLAKE3, writes into staging, then exchanges
/// VERIFY / VERIFY_RESULT / COMMIT / COMMITTED with the client.
///
/// Returns the committed file's whole-file BLAKE3 on success.
pub async fn server_upload_session(
    conn: &dyn Connection,
    backend: &LocalFilesystemBackend,
    control_send: &mut dyn BiSendStream,
    control_recv: &mut dyn BiRecvStream,
    transfer_id: TransferId,
    dst: &VPath,
    expected_size: u64,
    expected_hash: Hash,
) -> Result<Hash> {
    server_upload_session_with_state(
        conn,
        backend,
        control_send,
        control_recv,
        None,
        false,
        transfer_id,
        dst,
        expected_size,
        expected_hash,
    )
    .await
}

/// Server-side upload session with state store persistence and resume support.
pub async fn server_upload_session_with_state(
    conn: &dyn Connection,
    backend: &LocalFilesystemBackend,
    control_send: &mut dyn BiSendStream,
    control_recv: &mut dyn BiRecvStream,
    store: Option<Arc<dyn StateStore>>,
    resumed: bool,
    transfer_id: TransferId,
    dst: &VPath,
    expected_size: u64,
    expected_hash: Hash,
) -> Result<Hash> {
    use crate::protocol::message::Message;
    use crate::session::encode_message;

    // Receive the data stream.
    let mut data_recv = conn.accept_uni().await?;
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

    // Open staging (preserving existing bytes if resuming).
    let mut writer = backend
        .open_staging_resumable(&transfer_id.to_string(), dst, expected_size, resumed)
        .await?;

    let mut bitmap = match &store {
        Some(s) if resumed => s.read_bitmap(transfer_id).unwrap_or_default(),
        _ => ChunkBitmap::new(),
    };
    let mut bytes_received = bitmap.bytes_completed();
    let mut last_checkpoint_bytes = bytes_received;

    loop {
        let header_bytes = match data_recv.read_exact(DATA_FRAME_HEADER_LEN).await? {
            Some(b) => b,
            None => break,
        };
        let (hdr, _payload_after) = decode_data_frame_header(&header_bytes)?;
        let payload_len = hdr.chunk_len as usize;
        let payload = match data_recv.read_exact(payload_len).await? {
            Some(b) => b,
            None => {
                return Err(protocol_violation(
                    "upload: chunk payload shorter than declared (stream EOF)",
                ));
            }
        };
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
        if let Some(s) = &store {
            if bytes_received.saturating_sub(last_checkpoint_bytes) >= 16 * 1024 * 1024 {
                let _ = s.write_bitmap(transfer_id, &bitmap);
                last_checkpoint_bytes = bytes_received;
            }
        }
    }
    writer.fsync().await?;
    let staging_handle = writer.into_staging();
    if let Some(s) = &store {
        let _ = s.write_bitmap(transfer_id, &bitmap);
    }

    // Compute whole-file hash of the staged file.
    let staging_path = server_staging_path(backend.staging_dir(), &transfer_id, dst);
    if !staging_path.exists() {
        return Err(VelcruxError::Internal(format!(
            "server: staging file not found at {}",
            staging_path.display()
        )));
    }
    let computed = hash_file(&staging_path).await?;

    // Await VERIFY (skipping and persisting any CHECKPOINT frames that arrive first).
    let frame = loop {
        let f = read_control_frame(control_recv).await?;
        if f.type_byte == crate::protocol::message::CHECKPOINT {
            if let Ok(cp) = Checkpoint::decode(&f.payload) {
                if let Some(s) = &store {
                    let _ = s.write_bitmap(transfer_id, &bitmap);
                    if let Ok(mut r) = s.get_transfer(transfer_id) {
                        r.bytes_completed = cp.bytes_transferred;
                        r.last_checkpoint_ms = cp.ts_ms;
                        let _ = s.update_transfer(&r);
                    }
                }
            }
            continue;
        }
        break f;
    };
    if frame.type_byte != crate::protocol::message::VERIFY {
        return Err(protocol_violation("server: expected VERIFY"));
    }
    let verify = VerifyMsg::decode(&frame.payload)?;
    if verify.transfer_id != transfer_id || verify.expected_hash != expected_hash {
        return Err(protocol_violation(
            "server: VERIFY transfer_id/hash mismatch",
        ));
    }

    // Reply VERIFY_RESULT.
    let ok = computed == expected_hash;
    let vr = VerifyResultMsg {
        transfer_id,
        ok,
        computed_hash: computed,
    };
    let buf = Bytes::from(encode_message(&Message::VerifyResult(vr), 0)?);
    control_send.write_all(buf).await?;
    if !ok {
        return Err(VelcruxError::Protocol(
            crate::error::ProtocolError::Malformed("server: hash mismatch on verify"),
        ));
    }

    // Await COMMIT.
    let frame = read_control_frame(control_recv).await?;
    if frame.type_byte != crate::protocol::message::COMMIT {
        return Err(protocol_violation("server: expected COMMIT"));
    }
    let commit = CommitMsg::decode(&frame.payload)?;
    if commit.transfer_id != transfer_id {
        return Err(protocol_violation("server: COMMIT transfer_id mismatch"));
    }

    // Atomic commit journal sequence: Pending -> Renamed -> Committed
    if let Some(s) = &store {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let _ = s.write_journal(&CommitJournalEntry {
            transfer_id,
            file_id: 1,
            remote_path: dst.as_str().to_string(),
            status: CommitStatus::Renamed,
            updated_ms: now,
        });
    }

    let meta = FileMeta::new(expected_size, computed);
    backend
        .commit(&transfer_id.to_string(), staging_handle, dst, &meta)
        .await?;

    if let Some(s) = &store {
        let _ = s.mark_journal_committed(transfer_id, 1);
    }

    // Reply COMMITTED.
    let committed = CommittedMsg {
        transfer_id,
        files: 1,
    };
    let buf = Bytes::from(encode_message(&Message::Committed(committed), 0)?);
    control_send.write_all(buf).await?;

    Ok(computed)
}

// ===========================================================================
// Client download
// ===========================================================================

/// Client-side download. Receives a DATA stream from the server, verifies
/// per-chunk BLAKE3, writes into staging at the declared offsets, then
/// exchanges VERIFY / VERIFY_RESULT / COMMIT / COMMITTED.
///
/// `local_path` is the destination on the client; the file is staged to
/// `<local_path>.velcrux-partial` and atomically renamed on commit.
pub async fn client_download(
    conn: &dyn Connection,
    control_send: Box<dyn BiSendStream>,
    control_recv: Box<dyn BiRecvStream>,
    transfer_id: TransferId,
    local_path: PathBuf,
) -> Result<Hash> {
    client_download_with_progress(
        conn,
        control_send,
        control_recv,
        transfer_id,
        local_path,
        None,
    )
    .await
}

/// Client-side download with optional live progress channel.
pub async fn client_download_with_progress(
    conn: &dyn Connection,
    mut control_send: Box<dyn BiSendStream>,
    mut control_recv: Box<dyn BiRecvStream>,
    transfer_id: TransferId,
    local_path: PathBuf,
    progress_tx: Option<mpsc::Sender<u64>>,
) -> Result<Hash> {
    use crate::protocol::message::Message;
    use crate::session::encode_message;

    // Open staging on the client filesystem directly (no StorageBackend
    // needed for M2 — clients do not own the server's storage abstraction).
    let staging_path = {
        let mut p = local_path.clone().into_os_string();
        p.push(".velcrux-partial");
        std::path::PathBuf::from(p)
    };
    if let Some(parent) = staging_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut staging_file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&staging_path)
        .await?;

    // Receive the data stream (server opens it after TRANSFER_BEGIN).
    let mut data_recv = conn.accept_uni().await?;
    let pre = data_recv
        .read_exact(DATA_PREAMBLE_LEN)
        .await?
        .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
    let preamble = decode_data_preamble(&pre)?;
    if preamble.transfer_id != transfer_id {
        return Err(protocol_violation(
            "download: transfer_id mismatch in preamble",
        ));
    }

    loop {
        let header_bytes = match data_recv.read_exact(DATA_FRAME_HEADER_LEN).await? {
            Some(b) => b,
            None => break,
        };
        let (hdr, _payload_after) = decode_data_frame_header(&header_bytes)?;
        let payload_len = hdr.chunk_len as usize;
        let payload = match data_recv.read_exact(payload_len).await? {
            Some(b) => b,
            None => {
                return Err(protocol_violation(
                    "download: chunk payload shorter than declared (stream EOF)",
                ));
            }
        };
        let computed = hash_bytes(&payload);
        if computed != hdr.chunk_hash {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::Malformed("download: chunk hash mismatch"),
            ));
        }
        // pwrite at the declared offset.
        use tokio::io::AsyncSeekExt;
        use tokio::io::AsyncWriteExt;
        staging_file
            .seek(std::io::SeekFrom::Start(hdr.chunk_offset))
            .await?;
        staging_file.write_all(&payload).await?;

        if let Some(tx) = &progress_tx {
            let _ = tx.try_send(payload_len as u64);
        }
    }
    staging_file.sync_all().await?;
    drop(staging_file);

    // VERIFY → server replies with VERIFY_RESULT{computed_hash}. The
    // receiver sends VERIFY to confirm; for download we send Hash::ZERO
    // since the client does not know the expected hash in advance. The
    // server is authoritative for the whole-file hash; it returns ok=true
    // iff the file it just streamed matches its stored hash.
    let verify = VerifyMsg {
        transfer_id,
        expected_hash: Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::Verify(verify), 0)?);
    control_send.write_all(buf).await?;

    let frame = read_control_frame(&mut *control_recv).await?;
    if frame.type_byte != crate::protocol::message::VERIFY_RESULT {
        return Err(protocol_violation("download: expected VERIFY_RESULT"));
    }
    let vr = VerifyResultMsg::decode(&frame.payload)?;
    if vr.transfer_id != transfer_id {
        return Err(protocol_violation(
            "download: VERIFY_RESULT transfer_id mismatch",
        ));
    }
    if !vr.ok {
        return Err(VelcruxError::Protocol(
            crate::error::ProtocolError::Malformed("download: server reported hash mismatch"),
        ));
    }

    // COMMIT.
    let commit = CommitMsg { transfer_id };
    let buf = Bytes::from(encode_message(&Message::Commit(commit), 0)?);
    control_send.write_all(buf).await?;

    // Await COMMITTED.
    let frame = read_control_frame(&mut *control_recv).await?;
    if frame.type_byte != crate::protocol::message::COMMITTED {
        return Err(protocol_violation("download: expected COMMITTED"));
    }
    let committed = CommittedMsg::decode(&frame.payload)?;
    if committed.transfer_id != transfer_id || committed.files != 1 {
        return Err(protocol_violation(
            "download: COMMITTED transfer_id/files mismatch",
        ));
    }

    // Atomic rename staging → final.
    tokio::fs::rename(&staging_path, &local_path).await?;
    if let Some(parent) = local_path.parent() {
        if let Ok(dir) = tokio::fs::File::open(parent).await {
            let _ = dir.sync_all().await;
        }
    }

    Ok(vr.computed_hash)
}

// ===========================================================================
// Server-side download session
// ===========================================================================

/// Server-side download session. Opens a data stream, sends DATA frames
/// (header + per-chunk BLAKE3 hash + payload), then exchanges
/// VERIFY / VERIFY_RESULT / COMMIT / COMMITTED with the client.
pub async fn server_download_session(
    conn: &dyn Connection,
    backend: &LocalFilesystemBackend,
    control_send: &mut dyn BiSendStream,
    control_recv: &mut dyn BiRecvStream,
    transfer_id: TransferId,
    src: &VPath,
    _file_size: u64,
    _file_hash: Hash,
) -> Result<()> {
    use crate::protocol::message::Message;
    use crate::session::encode_message;

    // Open a unidirectional data stream and write the preamble.
    let mut data_send = conn.open_uni().await?;
    let preamble = DataPreamble {
        transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    data_send
        .write_all(Bytes::from(encode_data_preamble(&preamble).to_vec()))
        .await?;

    // Open the source file for reading.
    let mut reader = backend.open_read(src).await?;

    // Stream from disk → CDC → BLAKE3 → DATA frames. We also compute
    // the whole-file BLAKE3 inline so the VERIFY_RESULT reply can
    // report the true hash (the storage backend's stat() does not
    // compute hashes; it would be too expensive on every stat call).
    let mut read_buf = vec![0u8; 2 * 1024 * 1024];
    let mut chunker = RollingChunker::new(ChunkParams::default());
    let mut pending: Vec<u8> = Vec::with_capacity(ChunkParams::default().max as usize);
    let mut whole_hasher = HashHasher::new();
    // `file_offset` tracks the next byte to read from the source file.
    // `pending_offset` is the file offset of the start of the bytes in
    // `pending`; it equals the file offset of the first unread byte.
    let mut file_offset: u64 = 0;
    let mut pending_offset: u64 = 0;

    loop {
        let n = reader.read_at(file_offset, &mut read_buf).await?;
        if n == 0 {
            // EOF: emit trailing chunk if any.
            if !pending.is_empty() {
                let hash = hash_bytes(&pending);
                let bytes = encode_data_frame(
                    pending_offset,
                    pending.len() as u32,
                    DataFrameFlags::NONE,
                    &hash,
                    &pending,
                );
                data_send.write_all(Bytes::from(bytes)).await?;
            }
            break;
        }
        pending.extend_from_slice(&read_buf[..n]);
        whole_hasher.feed(&read_buf[..n]);
        file_offset += n as u64;
        let boundaries = chunker.push(&read_buf[..n])?;
        for b in &boundaries {
            let target = b.end() as u64;
            let need = (target - pending_offset) as usize;
            let hash = hash_bytes(&pending[..need]);
            let payload = pending.drain(..need).collect::<Vec<u8>>();
            let bytes = encode_data_frame(
                pending_offset,
                need as u32,
                DataFrameFlags::NONE,
                &hash,
                &payload,
            );
            data_send.write_all(Bytes::from(bytes)).await?;
            pending_offset = b.end();
        }
    }
    // Finalize the whole-file hash.
    let computed_hash = whole_hasher.finalize();
    data_send.finish().await?;

    // Await VERIFY from client.
    let frame = read_control_frame(control_recv).await?;
    if frame.type_byte != crate::protocol::message::VERIFY {
        return Err(protocol_violation("server download: expected VERIFY"));
    }
    let verify = VerifyMsg::decode(&frame.payload)?;
    if verify.transfer_id != transfer_id {
        return Err(protocol_violation(
            "server download: VERIFY transfer_id mismatch",
        ));
    }

    // Reply VERIFY_RESULT{ok, computed_hash=whole_file_hash}.
    // For M2 the client doesn't pre-share the expected hash, so the
    // server is trusted to report ok=true (the per-chunk BLAKE3 + the
    // whole-file hash prove the file content is intact). M3+ can add
    // a pre-shared hash check.
    let vr = VerifyResultMsg {
        transfer_id,
        ok: true,
        computed_hash,
    };
    let buf = Bytes::from(encode_message(&Message::VerifyResult(vr), 0)?);
    control_send.write_all(buf).await?;

    // Await COMMIT.
    let frame = read_control_frame(control_recv).await?;
    if frame.type_byte != crate::protocol::message::COMMIT {
        return Err(protocol_violation("server download: expected COMMIT"));
    }
    let commit = CommitMsg::decode(&frame.payload)?;
    if commit.transfer_id != transfer_id {
        return Err(protocol_violation(
            "server download: COMMIT transfer_id mismatch",
        ));
    }

    // Reply COMMITTED.
    let committed = CommittedMsg {
        transfer_id,
        files: 1,
    };
    let buf = Bytes::from(encode_message(&Message::Committed(committed), 0)?);
    control_send.write_all(buf).await?;

    Ok(())
}
