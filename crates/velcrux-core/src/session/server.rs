//! Server-side per-connection state machine.
//!
//! Per `PROTOCOL.md` §7 the server-side state machine for one connection is
//!
//! ```text
//! ACCEPTED → TLS_HANDSHAKE → AWAIT_HELLO → AWAIT_AUTH → AUTHENTICATED
//!   → SERVING (0..N transfers) → DRAINING → CLOSED
//! ```
//!
//! `ServerConn` is the per-connection actor. It drives a single
//! `control_stream` task: receive one HELLO, reply HELLO_ACK, await AUTH,
//! reply AUTH_OK, then loop receiving PING/PONG and other control messages
//! until the peer sends BYE or the connection drops.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::auth::{Authenticator, Authorizer, FileAuthorizer, MtlsAuthenticator, Op};
use crate::error::{Result, VelcruxError};
use crate::protocol::capabilities::Capabilities;
use crate::protocol::message::{Auth, AuthOk, Hello, HelloAck, Message, Ping};
use crate::state::{Direction, StateStore, TransferStatus};
use crate::storage::{LocalChunkStore, LocalFilesystemBackend, VPath};
use crate::transport::identity::Identity;
use crate::transport::Connection;
use std::sync::Arc;

use super::{read_frame, write_frame};

/// Per-connection state. The match in [`ServerConn::run`] has no wildcard
/// arm, so unknown message types or invalid transitions are
/// `PROTOCOL_VIOLATION` rather than silent fall-through (`PROTOCOL.md` §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// TCP/QUIC accept completed, before the TLS handshake.
    Accepted,
    /// TLS handshake in progress.
    TlsHandshake,
    /// Awaiting HELLO from the client.
    AwaitHello,
    /// Awaiting AUTH (M2).
    AwaitAuth,
    /// Authenticated; serving transfers (M2+). M1 handles PING/PONG here.
    Serving,
    /// Draining in response to a graceful shutdown.
    Draining,
    /// Connection is closed.
    Closed,
}

impl ServerState {
    /// Static name for logs and error messages.
    pub fn name(self) -> &'static str {
        match self {
            ServerState::Accepted => "ACCEPTED",
            ServerState::TlsHandshake => "TLS_HANDSHAKE",
            ServerState::AwaitHello => "AWAIT_HELLO",
            ServerState::AwaitAuth => "AWAIT_AUTH",
            ServerState::Serving => "SERVING",
            ServerState::Draining => "DRAINING",
            ServerState::Closed => "CLOSED",
        }
    }
}

/// Server-wide counters, exported in `ServerStats` for tests and `/metrics`.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Total connections accepted.
    pub connections: AtomicU64,
    /// Connections that completed HELLO/HELLO_ACK.
    pub handshakes: AtomicU64,
    /// PINGs handled.
    pub pings: AtomicU64,
    /// Active transfers currently running.
    pub transfers_active: AtomicU64,
    /// Total completed uploads.
    pub transfers_total_upload: AtomicU64,
    /// Total completed downloads.
    pub transfers_total_download: AtomicU64,
    /// Bytes transferred on wire for uploads.
    pub bytes_transferred_upload: AtomicU64,
    /// Bytes transferred on wire for downloads.
    pub bytes_transferred_download: AtomicU64,
    /// Bytes reused locally via delta/inventory.
    pub bytes_reused: AtomicU64,
    /// Total authorization denials.
    pub authz_denials: AtomicU64,
    /// Total checksum verification mismatches.
    pub checksum_mismatches: AtomicU64,
}

/// A per-connection actor. Constructed by `run`; runs to completion.
pub struct ServerConn {
    /// Server's full capabilities (used to compute the intersection).
    server_caps: Capabilities,
    /// Server's identity (name), for logs.
    server_name: String,
    /// Server-wide counters (Arc'd so a test can share them).
    stats: Arc<ServerStats>,
    /// Storage backend used by M2 transfer sessions.
    backend: Arc<LocalFilesystemBackend>,
    /// M3 state store. The server uses it to answer STAT / LIST
    /// queries and to update transfer status on CANCEL. The default
    /// is `None`, which disables the M3 surface (used by tests that
    /// don't exercise it).
    state: Option<Arc<dyn StateStore>>,
    /// Authenticator for mTLS.
    authenticator: Arc<dyn Authenticator>,
    /// Authorizer for path-based access control.
    authorizer: Arc<dyn Authorizer>,
    /// Optional content-addressed chunk store for cross-file deduplication.
    chunk_store: Option<Arc<LocalChunkStore>>,
}

impl ServerConn {
    /// Construct a new connection actor (M2 surface only).
    pub fn new(
        server_caps: Capabilities,
        server_name: impl Into<String>,
        stats: Arc<ServerStats>,
        backend: Arc<LocalFilesystemBackend>,
    ) -> Self {
        Self::with_state(server_caps, server_name, stats, backend, None, None, None)
    }

    /// Construct a new connection actor with the M3 state store
    /// wired in. Required to serve STAT / LIST / CANCEL.
    pub fn with_state(
        server_caps: Capabilities,
        server_name: impl Into<String>,
        stats: Arc<ServerStats>,
        backend: Arc<LocalFilesystemBackend>,
        state: Option<Arc<dyn StateStore>>,
        authenticator: Option<Arc<dyn Authenticator>>,
        authorizer: Option<Arc<dyn Authorizer>>,
    ) -> Self {
        let authenticator = authenticator.unwrap_or_else(|| Arc::new(MtlsAuthenticator::new()));
        let authorizer = authorizer.unwrap_or_else(|| Arc::new(FileAuthorizer::new()));
        Self {
            server_caps,
            server_name: server_name.into(),
            stats,
            backend,
            state,
            authenticator,
            authorizer,
            chunk_store: None,
        }
    }

    /// Attach an optional content-addressed LocalChunkStore for deduplication.
    pub fn with_chunk_store(mut self, chunk_store: Option<Arc<LocalChunkStore>>) -> Self {
        self.chunk_store = chunk_store;
        self
    }

    /// Drive the connection from `Accepted` through `Closed`. Returns the
    /// final state.
    pub async fn run(self, conn: &dyn Connection) -> Result<ServerState> {
        self.stats.connections.fetch_add(1, Ordering::Relaxed);
        let mut state = ServerState::AwaitHello;
        let (mut send, mut recv) = conn.accept_bi().await?;

        // Extract the peer identity from the TLS connection.
        let peer_identity = conn.peer_identity();

        // The identity verified during AWAIT_AUTH, carried into SERVING so
        // every operation is authorized against it. `None` until AUTH_OK.
        let mut authenticated_identity: Option<Identity> = None;

        loop {
            match state {
                ServerState::AwaitHello => {
                    let frame = match read_frame(recv.as_mut()).await? {
                        Some(f) => f,
                        None => break,
                    };
                    match frame.type_byte {
                        x if x == crate::protocol::message::HELLO => {
                            let hello = Hello::decode(&frame.payload)?;
                            let intersection = hello.capabilities.intersect(self.server_caps);
                            if let Err(s) = Capabilities::validate_intersection(intersection) {
                                let err = crate::protocol::message::ErrorMsg::new(
                                    crate::protocol::error::ErrorCode::ProtocolVersionUnsupported,
                                    s,
                                );
                                let _ = write_frame(
                                    send.as_mut(),
                                    &Message::Error(err),
                                    frame.request_id,
                                )
                                .await;
                                conn.close(
                                    crate::protocol::error::ErrorCode::ProtocolVersionUnsupported
                                        .to_wire(),
                                    b"no capability intersection",
                                );
                                state = ServerState::Closed;
                                break;
                            }
                            let ack = HelloAck {
                                version: crate::protocol::limits::PROTOCOL_VERSION,
                                capabilities: intersection,
                                limits: crate::protocol::message::Limits::default(),
                                agent: format!(
                                    "{}/{}",
                                    self.server_name,
                                    env!("CARGO_PKG_VERSION")
                                ),
                            };
                            write_frame(send.as_mut(), &Message::HelloAck(ack), frame.request_id)
                                .await?;
                            self.stats.handshakes.fetch_add(1, Ordering::Relaxed);
                            state = ServerState::AwaitAuth;
                        }
                        _other => {
                            return Err(VelcruxError::Protocol(
                                crate::error::ProtocolError::InvalidStateTransition(
                                    "expected HELLO",
                                ),
                            ));
                        }
                    }
                }
                ServerState::AwaitAuth => {
                    let frame = match read_frame(recv.as_mut()).await? {
                        Some(f) => f,
                        None => break,
                    };
                    match frame.type_byte {
                        x if x == crate::protocol::message::AUTH => {
                            let auth = Auth::decode(&frame.payload)?;
                            // Verify the peer identity is available.
                            let identity = peer_identity.clone().ok_or_else(|| {
                                VelcruxError::Protocol(
                                    crate::error::ProtocolError::InvalidIdentity(
                                        "no peer identity",
                                    ),
                                )
                            })?;

                            // Authenticate using the authenticator.
                            let verified_identity = self.authenticator.authenticate(&identity)?;

                            // For mTLS, the mechanism should be MTLS (0).
                            if auth.mechanism != crate::protocol::message::AUTH_MECHANISM_MTLS {
                                let err = crate::protocol::message::ErrorMsg::new(
                                    crate::protocol::error::ErrorCode::AuthFailed,
                                    "unsupported auth mechanism",
                                );
                                let _ = write_frame(
                                    send.as_mut(),
                                    &Message::Error(err),
                                    frame.request_id,
                                )
                                .await;
                                conn.close(
                                    crate::protocol::error::ErrorCode::AuthFailed.to_wire(),
                                    b"unsupported auth mechanism",
                                );
                                state = ServerState::Closed;
                                break;
                            }

                            // Permissions reported in AUTH_OK are the union of
                            // all grants for this identity (`SECURITY.md` §4).
                            // Advisory only: every individual operation is still
                            // authorized against its specific path in SERVING.
                            // An identity with no grants authenticates but is
                            // reported — and enforced — as having none.
                            let permissions = self
                                .authorizer
                                .granted_permissions(&verified_identity)
                                .to_wire();

                            let auth_ok = AuthOk {
                                identity: verified_identity.name.clone(),
                                permissions,
                            };
                            write_frame(send.as_mut(), &Message::AuthOk(auth_ok), frame.request_id)
                                .await?;

                            // Carry the verified identity into SERVING.
                            authenticated_identity = Some(verified_identity);
                            state = ServerState::Serving;
                        }
                        _other => {
                            return Err(VelcruxError::Protocol(
                                crate::error::ProtocolError::InvalidStateTransition(
                                    "expected AUTH",
                                ),
                            ));
                        }
                    }
                }
                ServerState::Serving => {
                    // Every op in SERVING is authorized against the identity
                    // verified during AWAIT_AUTH. Reaching SERVING without one
                    // is an internal invariant violation — fail closed, never
                    // panic and never serve unauthenticated.
                    let identity = match authenticated_identity.as_ref() {
                        Some(id) => id,
                        None => {
                            return Err(VelcruxError::Protocol(
                                crate::error::ProtocolError::InvalidStateTransition(
                                    "SERVING without authenticated identity",
                                ),
                            ));
                        }
                    };
                    let frame = match read_frame(recv.as_mut()).await? {
                        Some(f) => f,
                        None => break,
                    };
                    match frame.type_byte {
                        x if x == crate::protocol::message::PING => {
                            let ping = Ping::decode(&frame.payload)?;
                            let pong = Ping {
                                nonce: ping.nonce,
                                sender_ts_ms: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(0),
                            };
                            write_frame(send.as_mut(), &Message::Pong(pong), frame.request_id)
                                .await?;
                            self.stats.pings.fetch_add(1, Ordering::Relaxed);
                        }
                        x if x == crate::protocol::message::BYE => {
                            send.finish().await.ok();
                            state = ServerState::Closed;
                            break;
                        }
                        x if x == crate::protocol::message::TRANSFER_CREATE => {
                            // Dispatch to the transfer state machine. The path
                            // is authorized inside, before any filesystem I/O.
                            if let Err(e) = handle_transfer_create(
                                conn,
                                &self.backend,
                                self.authorizer.as_ref(),
                                &self.state,
                                &self.chunk_store,
                                identity,
                                send.as_mut(),
                                recv.as_mut(),
                                &frame.payload,
                                &self.stats,
                            )
                            .await
                            {
                                // Best-effort error reply; then continue.
                                tracing::warn!(error = %e, "transfer dispatch failed");
                            }
                        }
                        x if x == crate::protocol::message::RESUME => {
                            if let Err(e) = handle_resume(
                                conn,
                                &self.backend,
                                self.authorizer.as_ref(),
                                &self.state,
                                identity,
                                send.as_mut(),
                                recv.as_mut(),
                                &frame.payload,
                                frame.request_id,
                            )
                            .await
                            {
                                tracing::warn!(error = %e, "resume dispatch failed");
                            }
                        }
                        x if x == crate::protocol::message::STAT => {
                            handle_stat(
                                send.as_mut(),
                                &self.state,
                                self.authorizer.as_ref(),
                                identity,
                                &frame.payload,
                            )
                            .await;
                        }
                        x if x == crate::protocol::message::LIST => {
                            handle_list(
                                send.as_mut(),
                                &self.state,
                                self.authorizer.as_ref(),
                                identity,
                                &frame.payload,
                            )
                            .await;
                        }
                        x if x == crate::protocol::message::CANCEL => {
                            handle_cancel(
                                send.as_mut(),
                                &self.backend,
                                &self.state,
                                self.authorizer.as_ref(),
                                identity,
                                &frame.payload,
                            )
                            .await;
                        }
                        other => {
                            let err = crate::protocol::message::ErrorMsg::new(
                                crate::protocol::error::ErrorCode::UnsupportedMessage,
                                "unsupported",
                            );
                            let _ =
                                write_frame(send.as_mut(), &Message::Error(err), frame.request_id)
                                    .await;
                            tracing::debug!(
                                state = state.name(),
                                "unsupported message 0x{other:02x}"
                            );
                        }
                    }
                }
                ServerState::Closed => break,
                ServerState::Accepted | ServerState::TlsHandshake | ServerState::Draining => {
                    return Err(VelcruxError::Protocol(
                        crate::error::ProtocolError::InvalidStateTransition(state.name()),
                    ));
                }
            }
        }
        Ok(state)
    }
}

/// Handle a `TRANSFER_CREATE` request: validate path, issue
/// `TRANSFER_CREATED` + `TRANSFER_PLAN`, await `TRANSFER_BEGIN`, then run
/// the per-transfer upload or download session.
///
/// The destination path is authorized against `identity` **before** any
/// filesystem access (`stat`, staging). On any authorization or validation
/// failure the reply is a uniform `FILE_NOT_FOUND` / "not found", so a
/// caller cannot distinguish "denied", "malformed path", and "does not
/// exist" (`PROTOCOL.md` §10).
struct ActiveTransferGuard<'a>(&'a std::sync::atomic::AtomicU64);
impl<'a> Drop for ActiveTransferGuard<'a> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn handle_transfer_create(
    conn: &dyn Connection,
    backend: &LocalFilesystemBackend,
    authorizer: &dyn Authorizer,
    state: &Option<Arc<dyn StateStore>>,
    chunk_store: &Option<Arc<LocalChunkStore>>,
    identity: &Identity,
    send: &mut dyn crate::transport::BiSendStream,
    recv: &mut dyn crate::transport::BiRecvStream,
    payload: &[u8],
    stats: &ServerStats,
) -> Result<()> {
    use crate::protocol::limits::MAX_CHUNK_SIZE;
    use crate::protocol::message::{
        Commit, Committed, Message, TransferBegin, TransferCreate, TransferCreated, TransferOp,
        TransferPlan,
    };
    use crate::storage::StorageBackend;
    use crate::util::TransferId;

    let create = TransferCreate::decode(payload)?;

    if create.op == TransferOp::Delete {
        let dst = match authorizer.check(identity, Op::Delete, &create.dst_path) {
            Ok(p) => p,
            Err(_) => {
                stats
                    .authz_denials
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let err = crate::protocol::message::ErrorMsg::new(
                    crate::protocol::error::ErrorCode::FileNotFound,
                    "not found",
                );
                write_frame(send, &Message::Error(err), 0).await?;
                return Ok(());
            }
        };
        let transfer_id = TransferId::generate();
        let _ = backend.remove(&dst).await;
        let committed = Committed {
            transfer_id,
            files: 1,
        };
        write_frame(send, &Message::Committed(committed), 0).await?;
        return Ok(());
    }

    if create.op == TransferOp::SyncUpload || create.op == TransferOp::SyncDownload {
        let target_path = if create.op == TransferOp::SyncUpload {
            &create.dst_path
        } else {
            &create.src_path
        };
        let vpath = match authorizer.check(identity, Op::Sync, target_path) {
            Ok(p) => p,
            Err(_) => {
                stats
                    .authz_denials
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let err = crate::protocol::message::ErrorMsg::new(
                    crate::protocol::error::ErrorCode::FileNotFound,
                    "not found",
                );
                write_frame(send, &Message::Error(err), 0).await?;
                return Ok(());
            }
        };

        let transfer_id = TransferId::generate();
        let created = TransferCreated {
            transfer_id,
            resumed: false,
            max_chunk_size: MAX_CHUNK_SIZE,
        };
        write_frame(send, &Message::TransferCreated(created), 0).await?;

        let server_dir = backend.root().join(vpath.as_path());
        let entries = crate::sync::scan_dir_entries(&server_dir).unwrap_or_default();
        crate::sync::send_directory_manifest(send, &entries).await?;
        return Ok(());
    }

    // Authorize the destination path for the requested operation BEFORE any
    // filesystem access. This both validates the path (traversal, absolute,
    // control chars) and enforces the identity's grants. Any failure →
    // uniform "not found".
    let op = match create.op {
        TransferOp::Upload => Op::Upload,
        TransferOp::Download => Op::Download,
        _ => unreachable!(),
    };
    let dst = match authorizer.check(identity, op, &create.dst_path) {
        Ok(p) => p,
        Err(_) => {
            stats
                .authz_denials
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let err = crate::protocol::message::ErrorMsg::new(
                crate::protocol::error::ErrorCode::FileNotFound,
                "not found",
            );
            write_frame(send, &Message::Error(err), 0).await?;
            return Ok(());
        }
    };

    stats
        .transfers_active
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _active_guard = ActiveTransferGuard(&stats.transfers_active);

    let (transfer_id, resumed, bytes_reusable) = match state {
        Some(store) => {
            match store
                .get_transfer_by_idempotency(crate::state::Role::Server, &create.idempotency_key)
            {
                Ok(existing) => {
                    let reusable = match store.read_bitmap(existing.transfer_id) {
                        Ok(bm) => bm.bytes_completed(),
                        Err(_) => 0,
                    };
                    (existing.transfer_id, true, reusable)
                }
                Err(_) => (TransferId::generate(), false, 0),
            }
        }
        None => (TransferId::generate(), false, 0),
    };

    let bytes_total = match create.op {
        TransferOp::Upload => create.file_size,
        TransferOp::Download => match backend.stat(&dst).await? {
            Some(m) => m.size,
            None => {
                let err = crate::protocol::message::ErrorMsg::new(
                    crate::protocol::error::ErrorCode::FileNotFound,
                    "not found",
                );
                write_frame(send, &Message::Error(err), 0).await?;
                return Ok(());
            }
        },
        _ => unreachable!(),
    };

    if let Some(store) = state {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let record = crate::state::TransferRecord {
            transfer_id,
            idempotency_key: create.idempotency_key.clone(),
            role: crate::state::Role::Server,
            direction: match create.op {
                TransferOp::Upload => Direction::Upload,
                TransferOp::Download => Direction::Download,
                _ => unreachable!(),
            },
            status: TransferStatus::Active,
            remote_path: create.dst_path.clone(),
            local_path: String::new(),
            file_size: bytes_total,
            file_hash: create.file_hash,
            verified_up_to: 0,
            last_checkpoint_ms: now,
            bytes_completed: bytes_reusable,
            staging_relpath: format!("{}/{}", transfer_id, dst.as_path().display()),
            created_ms: now,
            updated_ms: now,
        };
        if let Err(e) = store.upsert_transfer(&record) {
            tracing::warn!("server: upsert_transfer failed for {transfer_id}: {e}");
        }
        if create.op == TransferOp::Upload {
            let _ = store.write_journal(&crate::state::CommitJournalEntry {
                transfer_id,
                file_id: 1,
                remote_path: create.dst_path.clone(),
                status: crate::state::CommitStatus::Pending,
                updated_ms: now,
            });
        }
    }

    let existing_path = backend.root().join(dst.as_path());
    let has_existing = existing_path.is_file();
    let has_chunk_store = chunk_store.is_some();

    if create.op == TransferOp::Upload && (has_existing || has_chunk_store) {
        let meta_len = if has_existing {
            std::fs::metadata(&existing_path)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };
        let existing_hash = if has_existing {
            crate::sync::compute_file_hash(&existing_path).ok()
        } else {
            None
        };

        // Fast-path: Identical file already exists on server
        if has_existing && existing_hash == Some(create.file_hash) && meta_len == create.file_size {
            let created = TransferCreated {
                transfer_id,
                resumed: false,
                max_chunk_size: MAX_CHUNK_SIZE,
            };
            let plan = TransferPlan {
                transfer_id,
                bytes_total,
                bytes_to_transfer: 0,
                bytes_reusable: bytes_total,
            };
            write_frame(send, &Message::TransferCreated(created), 0).await?;
            write_frame(send, &Message::TransferPlan(plan), 0).await?;

            let frame = read_frame(recv)
                .await?
                .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
            if frame.type_byte != crate::protocol::message::TRANSFER_BEGIN {
                return Err(VelcruxError::Protocol(
                    crate::error::ProtocolError::InvalidStateTransition("expected TRANSFER_BEGIN"),
                ));
            }

            let frame = read_frame(recv)
                .await?
                .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
            if frame.type_byte == crate::protocol::message::VERIFY {
                let vr = crate::protocol::message::VerifyResult {
                    transfer_id,
                    ok: true,
                    computed_hash: create.file_hash,
                };
                write_frame(send, &Message::VerifyResult(vr), 0).await?;

                let frame = read_frame(recv)
                    .await?
                    .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
                if frame.type_byte == crate::protocol::message::COMMIT {
                    let committed = crate::protocol::message::Committed {
                        transfer_id,
                        files: 1,
                    };
                    write_frame(send, &Message::Committed(committed), 0).await?;
                    stats
                        .transfers_total_upload
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    stats
                        .bytes_reused
                        .fetch_add(bytes_total, std::sync::atomic::Ordering::Relaxed);

                    // If chunk store is enabled, ensure this file is indexed
                    if let Some(cs) = chunk_store {
                        let params =
                            crate::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024)
                                .unwrap();
                        let _ = cs.ingest_file_sync(
                            &existing_path,
                            crate::chunking::ChunkMode::Fixed,
                            params,
                        );
                    }
                }
            }
            return Ok(());
        }

        // Delta / Deduplication path: Destination file exists OR chunk store is available.
        let inv_opt = if has_existing {
            crate::sync::LocalInventory::from_file(
                &existing_path,
                crate::chunking::ChunkMode::Fixed,
                crate::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap(),
                64 * 1024,
            )
            .ok()
        } else {
            None
        };

        if inv_opt.is_some() || has_chunk_store {
            let created = TransferCreated {
                transfer_id,
                resumed: false,
                max_chunk_size: MAX_CHUNK_SIZE,
            };
            write_frame(send, &Message::TransferCreated(created), 0).await?;

            let bloom = match (&inv_opt, chunk_store) {
                (Some(inv), Some(cs)) => {
                    let mut b = cs.bloom_filter();
                    for h in inv.chunk_hashes() {
                        b.insert(h);
                    }
                    b
                }
                (Some(inv), None) => inv.create_bloom_filter(0.01),
                (None, Some(cs)) => cs.bloom_filter(),
                (None, None) => unreachable!(),
            };

            let hint = crate::protocol::message::InventoryHint {
                transfer_id,
                filter_bits: bloom.num_bits(),
                num_hashes: bloom.num_hashes(),
                bitset: bytes::Bytes::copy_from_slice(bloom.bitset_bytes()),
            };
            write_frame(send, &Message::InventoryHint(hint), 0).await?;

            let frame = read_frame(recv)
                .await?
                .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
            if frame.type_byte == crate::protocol::message::CHUNK_QUERY {
                let query = crate::protocol::message::ChunkQuery::decode(&frame.payload)?;
                let mut have_bits = Vec::with_capacity(query.chunk_hashes.len());
                let mut matching_chunks = Vec::new();
                let mut matching_store_chunks = Vec::new();
                for (idx, h) in query.chunk_hashes.iter().enumerate() {
                    let dst_off = idx as u64 * (64 * 1024);
                    let chunk_len = (create.file_size - dst_off).min(64 * 1024);
                    if let Some(extent) = inv_opt.as_ref().and_then(|inv| inv.lookup(h)) {
                        have_bits.push(true);
                        matching_chunks.push((dst_off, extent.offset, extent.length));
                    } else if chunk_store
                        .as_ref()
                        .map(|cs| cs.contains_sync(h))
                        .unwrap_or(false)
                    {
                        have_bits.push(true);
                        matching_store_chunks.push((dst_off, *h, chunk_len));
                    } else {
                        have_bits.push(false);
                    }
                }
                let rle = crate::sync::RleBitmap::from_bits(&have_bits);
                let resp = crate::protocol::message::ChunkResponse {
                    transfer_id,
                    query_seq: query.query_seq,
                    total_chunks: rle.total_chunks(),
                    have_count: rle.have_count(),
                    rle_bitmap: rle.encode(),
                };
                write_frame(send, &Message::ChunkResponse(resp), 0).await?;

                // Pre-stage matching chunks into staging file on server
                let staging_path = backend.staging_path(&transfer_id.to_string(), &dst);
                if let Some(parent) = staging_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                let mut staging_f = std::fs::OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .truncate(true)
                    .open(&staging_path)?;
                staging_f.set_len(create.file_size)?;

                let mut initial_bitmap = crate::state::ChunkBitmap::new();

                // 1. Copy from existing destination file
                if has_existing && !matching_chunks.is_empty() {
                    if let Ok(mut src_f) = std::fs::File::open(&existing_path) {
                        use std::io::{Read, Seek, SeekFrom, Write};
                        let mut copy_buf = [0u8; 64 * 1024];
                        for (dst_offset, src_offset, len) in matching_chunks {
                            src_f.seek(SeekFrom::Start(src_offset))?;
                            staging_f.seek(SeekFrom::Start(dst_offset))?;
                            let mut rem = len;
                            while rem > 0 {
                                let to_read = (rem as usize).min(copy_buf.len());
                                src_f.read_exact(&mut copy_buf[..to_read])?;
                                staging_f.write_all(&copy_buf[..to_read])?;
                                rem -= to_read as u64;
                            }
                            let chunk_idx = dst_offset / (64 * 1024);
                            initial_bitmap.mark_complete(chunk_idx, len);
                        }
                    }
                }

                // 2. Copy from content-addressed chunk store
                if let Some(cs) = chunk_store {
                    for (dst_offset, hash, len) in matching_store_chunks {
                        let _ = cs.copy_to_std_file(&hash, &mut staging_f, dst_offset);
                        let chunk_idx = dst_offset / (64 * 1024);
                        initial_bitmap.mark_complete(chunk_idx, len);
                    }
                }

                staging_f.sync_all()?;
                drop(staging_f);

                let bytes_reusable = initial_bitmap.bytes_completed();
                let plan = TransferPlan {
                    transfer_id,
                    bytes_total,
                    bytes_to_transfer: bytes_total.saturating_sub(bytes_reusable),
                    bytes_reusable,
                };
                write_frame(send, &Message::TransferPlan(plan), 0).await?;

                let begin_frame = read_frame(recv)
                    .await?
                    .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
                if begin_frame.type_byte != crate::protocol::message::TRANSFER_BEGIN {
                    return Err(VelcruxError::Protocol(
                        crate::error::ProtocolError::InvalidStateTransition(
                            "expected TRANSFER_BEGIN",
                        ),
                    ));
                }

                if plan.bytes_to_transfer == 0 {
                    let frame = read_frame(recv).await?.ok_or_else(|| {
                        VelcruxError::Protocol(crate::error::ProtocolError::Empty)
                    })?;
                    if frame.type_byte != crate::protocol::message::VERIFY {
                        return Err(VelcruxError::Protocol(
                            crate::error::ProtocolError::InvalidStateTransition("expected VERIFY"),
                        ));
                    }
                    let hash = crate::sync::compute_file_hash(&staging_path)?;
                    let ok = hash == create.file_hash;
                    let vr = crate::protocol::message::VerifyResult {
                        transfer_id,
                        ok,
                        computed_hash: hash,
                    };
                    write_frame(send, &Message::VerifyResult(vr), 0).await?;
                    if !ok {
                        return Err(VelcruxError::Protocol(
                            crate::error::ProtocolError::Malformed("checksum mismatch"),
                        ));
                    }
                    let frame = read_frame(recv).await?.ok_or_else(|| {
                        VelcruxError::Protocol(crate::error::ProtocolError::Empty)
                    })?;
                    if frame.type_byte != crate::protocol::message::COMMIT {
                        return Err(VelcruxError::Protocol(
                            crate::error::ProtocolError::InvalidStateTransition("expected COMMIT"),
                        ));
                    }
                    let final_path = backend.root().join(dst.as_path());
                    if let Some(parent) = final_path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    tokio::fs::rename(&staging_path, &final_path).await?;
                    let committed = crate::protocol::message::Committed {
                        transfer_id,
                        files: 1,
                    };
                    write_frame(send, &Message::Committed(committed), 0).await?;
                    stats
                        .transfers_total_upload
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    stats
                        .bytes_reused
                        .fetch_add(plan.bytes_reusable, std::sync::atomic::Ordering::Relaxed);
                    if let Some(cs) = chunk_store {
                        let final_path = backend.root().join(dst.as_path());
                        let params =
                            crate::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024)
                                .unwrap();
                        let _ = cs.ingest_file_sync(
                            &final_path,
                            crate::chunking::ChunkMode::Fixed,
                            params,
                        );
                    }
                    return Ok(());
                }

                let res = crate::transfer::server_upload_session_with_delta(
                    conn,
                    backend,
                    send,
                    recv,
                    state.clone(),
                    true,
                    transfer_id,
                    &dst,
                    create.file_size,
                    create.file_hash,
                    Some(initial_bitmap),
                )
                .await
                .map(|_| ());
                if res.is_ok() {
                    stats
                        .transfers_total_upload
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    stats
                        .bytes_transferred_upload
                        .fetch_add(plan.bytes_to_transfer, std::sync::atomic::Ordering::Relaxed);
                    stats
                        .bytes_reused
                        .fetch_add(plan.bytes_reusable, std::sync::atomic::Ordering::Relaxed);

                    // Ingest newly committed file into chunk store for future cross-file deduplication
                    if let Some(cs) = chunk_store {
                        let final_path = backend.root().join(dst.as_path());
                        let params =
                            crate::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024)
                                .unwrap();
                        let _ = cs.ingest_file_sync(
                            &final_path,
                            crate::chunking::ChunkMode::Fixed,
                            params,
                        );
                    }
                } else {
                    stats
                        .checksum_mismatches
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                return res;
            }
        }
    }

    let created = TransferCreated {
        transfer_id,
        resumed,
        max_chunk_size: MAX_CHUNK_SIZE,
    };
    let plan = TransferPlan {
        transfer_id,
        bytes_total,
        bytes_to_transfer: bytes_total.saturating_sub(bytes_reusable),
        bytes_reusable,
    };
    write_frame(send, &Message::TransferCreated(created), 0).await?;
    write_frame(send, &Message::TransferPlan(plan), 0).await?;

    // Await TRANSFER_BEGIN (or INVENTORY_HINT for download).
    let frame = read_frame(recv)
        .await?
        .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;

    let mut download_skip_bitmap = None;
    let begin_frame = if create.op == TransferOp::Download
        && frame.type_byte == crate::protocol::message::INVENTORY_HINT
    {
        let hint = crate::protocol::message::InventoryHint::decode(&frame.payload)?;
        let _bloom =
            crate::sync::BloomFilter::from_bytes(&hint.bitset, hint.filter_bits, hint.num_hashes)
                .map_err(|_| {
                VelcruxError::Protocol(crate::error::ProtocolError::Malformed("invalid bloom"))
            })?;

        let server_file_path = backend.root().join(dst.as_path());
        let mut sf = std::fs::File::open(&server_file_path)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut chunk_hashes = Vec::new();
        let mut chunk_indices = Vec::new();
        let mut offset = 0u64;
        let mut c_idx = 0u64;
        use std::io::Read;
        while offset < bytes_total {
            let to_read = ((bytes_total - offset).min(64 * 1024)) as usize;
            sf.read_exact(&mut buf[..to_read])?;
            let h = crate::util::Hash::of(&buf[..to_read]);
            chunk_hashes.push(h);
            chunk_indices.push((c_idx, to_read as u64));
            offset += to_read as u64;
            c_idx += 1;
        }

        let query = crate::protocol::message::ChunkQuery {
            transfer_id,
            query_seq: 1,
            chunk_hashes,
        };
        write_frame(send, &Message::ChunkQuery(query), 0).await?;

        let resp_frame = read_frame(recv)
            .await?
            .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
        if resp_frame.type_byte != crate::protocol::message::CHUNK_RESPONSE {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::InvalidStateTransition("expected CHUNK_RESPONSE"),
            ));
        }
        let resp = crate::protocol::message::ChunkResponse::decode(&resp_frame.payload)?;
        let rle =
            crate::sync::RleBitmap::decode(&resp.rle_bitmap, resp.total_chunks).map_err(|_| {
                VelcruxError::Protocol(crate::error::ProtocolError::Malformed("invalid rle"))
            })?;
        let mut bm = crate::state::ChunkBitmap::new();
        for (i, &(idx, len)) in chunk_indices.iter().enumerate() {
            if rle.get(i) == Some(true) {
                bm.mark_complete(idx, len);
            }
        }
        let bytes_reusable = bm.bytes_completed();
        download_skip_bitmap = Some(bm);

        let plan = TransferPlan {
            transfer_id,
            bytes_total,
            bytes_to_transfer: bytes_total.saturating_sub(bytes_reusable),
            bytes_reusable,
        };
        write_frame(send, &Message::TransferPlan(plan), 0).await?;

        read_frame(recv)
            .await?
            .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?
    } else {
        frame
    };

    if begin_frame.type_byte != crate::protocol::message::TRANSFER_BEGIN {
        return Err(VelcruxError::Protocol(
            crate::error::ProtocolError::InvalidStateTransition("expected TRANSFER_BEGIN"),
        ));
    }
    let begin = TransferBegin::decode(&begin_frame.payload)?;
    if begin.transfer_id != transfer_id {
        return Err(VelcruxError::Protocol(
            crate::error::ProtocolError::InvalidStateTransition(
                "TRANSFER_BEGIN transfer_id mismatch",
            ),
        ));
    }

    let res = match create.op {
        TransferOp::Upload => crate::transfer::server_upload_session_with_state(
            conn,
            backend,
            send,
            recv,
            state.clone(),
            resumed,
            transfer_id,
            &dst,
            create.file_size,
            create.file_hash,
        )
        .await
        .map(|_| ()),
        TransferOp::Download => {
            let file_hash = match backend.stat(&dst).await? {
                Some(m) => m.file_hash,
                None => {
                    let err = crate::protocol::message::ErrorMsg::new(
                        crate::protocol::error::ErrorCode::FileNotFound,
                        "not found",
                    );
                    write_frame(send, &Message::Error(err), 0).await?;
                    return Ok(());
                }
            };
            crate::transfer::server_download_session_with_delta(
                conn,
                backend,
                send,
                recv,
                transfer_id,
                &dst,
                bytes_total,
                file_hash,
                download_skip_bitmap,
            )
            .await
        }
        _ => unreachable!(),
    };

    if let Some(store) = state {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if res.is_ok() {
            if let Ok(mut record) = store.get_transfer(transfer_id) {
                record.status = TransferStatus::Committed;
                record.bytes_completed = bytes_total;
                record.verified_up_to = bytes_total;
                record.updated_ms = now;
                let _ = store.update_transfer(&record);
            }
            if create.op == TransferOp::Upload {
                let _ = store.mark_journal_committed(transfer_id, 1);
            }
        }
    }

    let _ = Committed {
        transfer_id,
        files: 1,
    };
    let _ = Commit { transfer_id };

    if res.is_ok() {
        match create.op {
            TransferOp::Upload => {
                stats
                    .transfers_total_upload
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats
                    .bytes_transferred_upload
                    .fetch_add(bytes_total, std::sync::atomic::Ordering::Relaxed);
            }
            TransferOp::Download => {
                stats
                    .transfers_total_download
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats
                    .bytes_transferred_download
                    .fetch_add(bytes_total, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
    } else {
        stats
            .checksum_mismatches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    res
}

async fn handle_resume(
    conn: &dyn Connection,
    backend: &Arc<LocalFilesystemBackend>,
    authorizer: &dyn Authorizer,
    state: &Option<Arc<dyn StateStore>>,
    identity: &Identity,
    send: &mut dyn crate::transport::BiSendStream,
    recv: &mut dyn crate::transport::BiRecvStream,
    payload: &[u8],
    request_id: u64,
) -> Result<()> {
    use crate::protocol::message::{Message, Resume, ResumeState, TransferBegin};

    let resume = match Resume::decode(payload) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    let Some(store) = state else {
        let err = crate::protocol::message::ErrorMsg::new(
            crate::protocol::error::ErrorCode::FileNotFound,
            "not found",
        );
        let _ = write_frame(send, &Message::Error(err), request_id).await;
        return Ok(());
    };

    let record = match store.get_transfer(resume.transfer_id) {
        Ok(r) => r,
        Err(_) => match store
            .get_transfer_by_idempotency(crate::state::Role::Server, &resume.idempotency_key)
        {
            Ok(r) => r,
            Err(_) => {
                let err = crate::protocol::message::ErrorMsg::new(
                    crate::protocol::error::ErrorCode::FileNotFound,
                    "not found",
                );
                let _ = write_frame(send, &Message::Error(err), request_id).await;
                return Ok(());
            }
        },
    };

    let op = match record.direction {
        Direction::Upload => Op::Resume,
        Direction::Download => Op::Download,
    };
    if authorizer.check(identity, op, &record.remote_path).is_err() {
        let err = crate::protocol::message::ErrorMsg::new(
            crate::protocol::error::ErrorCode::FileNotFound,
            "not found",
        );
        let _ = write_frame(send, &Message::Error(err), request_id).await;
        return Ok(());
    }

    let bitmap = store.read_bitmap(record.transfer_id).unwrap_or_default();
    let rs = ResumeState {
        transfer_id: record.transfer_id,
        staging_relpath: record.staging_relpath.clone(),
        file_size: record.file_size,
        bytes_completed: bitmap.bytes_completed(),
        verified_up_to: record.verified_up_to,
        file_hash: record.file_hash,
        completed_chunks: bitmap.indices().collect(),
    };
    write_frame(send, &Message::ResumeState(rs), request_id).await?;

    // Await TRANSFER_BEGIN.
    let frame = read_frame(recv)
        .await?
        .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
    if frame.type_byte != crate::protocol::message::TRANSFER_BEGIN {
        return Err(VelcruxError::Protocol(
            crate::error::ProtocolError::InvalidStateTransition("expected TRANSFER_BEGIN"),
        ));
    }
    let begin = TransferBegin::decode(&frame.payload)?;
    if begin.transfer_id != record.transfer_id {
        return Err(VelcruxError::Protocol(
            crate::error::ProtocolError::InvalidStateTransition(
                "TRANSFER_BEGIN transfer_id mismatch",
            ),
        ));
    }

    let dst = VPath::validate(&record.remote_path)?;
    let res = match record.direction {
        Direction::Upload => crate::transfer::server_upload_session_with_state(
            conn,
            backend,
            send,
            recv,
            state.clone(),
            true,
            record.transfer_id,
            &dst,
            record.file_size,
            record.file_hash,
        )
        .await
        .map(|_| ()),
        Direction::Download => {
            crate::transfer::server_download_session(
                conn,
                backend,
                send,
                recv,
                record.transfer_id,
                &dst,
                record.file_size,
                record.file_hash,
            )
            .await
        }
    };

    if res.is_ok() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut r) = store.get_transfer(record.transfer_id) {
            r.status = TransferStatus::Committed;
            r.bytes_completed = record.file_size;
            r.verified_up_to = record.file_size;
            r.updated_ms = now;
            let _ = store.update_transfer(&r);
        }
    }
    res
}

/// M3 server-side handler for `STAT`. Looks up the transfer in the
/// state DB and replies with `STAT_RESULT`.
///
/// The record's `remote_path` is authorized against `identity` (LIST): a
/// caller that may not list the path gets the same `found: false` reply as
/// for a genuinely unknown transfer, so STAT cannot be used to probe the
/// existence of another tenant's transfers (`PROTOCOL.md` §10).
async fn handle_stat(
    send: &mut dyn crate::transport::BiSendStream,
    state: &Option<Arc<dyn StateStore>>,
    authorizer: &dyn Authorizer,
    identity: &Identity,
    payload: &[u8],
) {
    use crate::protocol::message::{ListResult, Message, StatQuery, StatResult};

    let q = match StatQuery::decode(payload) {
        Ok(q) => q,
        Err(_) => return,
    };
    let sr = match state {
        Some(store) => match store.get_transfer(q.transfer_id) {
            Ok(r) if authorizer.check(identity, Op::List, &r.remote_path).is_ok() => StatResult {
                transfer_id: r.transfer_id,
                found: true,
                status: r.status.name().to_string(),
                direction: r.direction.name().to_string(),
                remote_path: r.remote_path,
                file_size: r.file_size,
                bytes_completed: r.bytes_completed,
                verified_up_to: r.verified_up_to,
                created_ms: r.created_ms,
                updated_ms: r.updated_ms,
            },
            // Unknown transfer OR not authorized to list its path — identical
            // reply (`PROTOCOL.md` §10).
            _ => StatResult {
                transfer_id: q.transfer_id,
                found: false,
                status: "missing".into(),
                direction: "".into(),
                remote_path: "".into(),
                file_size: 0,
                bytes_completed: 0,
                verified_up_to: 0,
                created_ms: 0,
                updated_ms: 0,
            },
        },
        None => StatResult {
            transfer_id: q.transfer_id,
            found: false,
            status: "no_state".into(),
            direction: "".into(),
            remote_path: "".into(),
            file_size: 0,
            bytes_completed: 0,
            verified_up_to: 0,
            created_ms: 0,
            updated_ms: 0,
        },
    };
    let _ = write_frame(send, &Message::StatResult(sr), 0).await;
    let _ = ListResult::decode; // keep import live
}

/// M3 server-side handler for `LIST`. Replies with a `LIST_RESULT`
/// of all transfers whose `remote_path` starts with the prefix **and**
/// that `identity` is authorized to list. Rows outside the caller's grants
/// are silently filtered out, so LIST never reveals another tenant's paths.
async fn handle_list(
    send: &mut dyn crate::transport::BiSendStream,
    state: &Option<Arc<dyn StateStore>>,
    authorizer: &dyn Authorizer,
    identity: &Identity,
    payload: &[u8],
) {
    use crate::protocol::message::{ListQuery, ListResult, Message, StatResult};

    let q = match ListQuery::decode(payload) {
        Ok(q) => q,
        Err(_) => return,
    };
    let clean_prefix = q.url_prefix.trim_start_matches('/');
    let entries: Vec<StatResult> = match state {
        Some(store) => {
            match store.list_transfers_by_path(crate::state::Role::Server, clean_prefix) {
                Ok(rows) => rows
                    .into_iter()
                    .filter(|r| authorizer.check(identity, Op::List, &r.remote_path).is_ok())
                    .map(|r| StatResult {
                        transfer_id: r.transfer_id,
                        found: true,
                        status: r.status.name().to_string(),
                        direction: r.direction.name().to_string(),
                        remote_path: r.remote_path,
                        file_size: r.file_size,
                        bytes_completed: r.bytes_completed,
                        verified_up_to: r.verified_up_to,
                        created_ms: r.created_ms,
                        updated_ms: r.updated_ms,
                    })
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
        None => Vec::new(),
    };
    let lr = ListResult { entries };
    let _ = write_frame(send, &Message::ListResult(lr), 0).await;
}

/// M3 server-side handler for `CANCEL`. Marks the transfer as
/// cancelled in the state DB and best-effort removes the staging
/// file. There is no reply on the wire; the client uses BYE.
///
/// The transfer is authorized against `identity` before it is touched: the
/// caller must hold the permission its direction implies (upload/download)
/// on the transfer's own path. An unknown transfer and an unauthorized one
/// are both silently ignored, so CANCEL cannot probe or affect another
/// tenant's transfers.
async fn handle_cancel(
    _send: &mut dyn crate::transport::BiSendStream,
    backend: &Arc<LocalFilesystemBackend>,
    state: &Option<Arc<dyn StateStore>>,
    authorizer: &dyn Authorizer,
    identity: &Identity,
    payload: &[u8],
) {
    use crate::protocol::message::Cancel;
    use crate::transfer::cancel_transfer_m3;

    let c = match Cancel::decode(payload) {
        Ok(c) => c,
        Err(_) => return,
    };
    let Some(store) = state else { return };
    // Look up the transfer so we can authorize against its own path. Unknown
    // transfer → silently ignore (indistinguishable from unauthorized).
    let record = match store.get_transfer(c.transfer_id) {
        Ok(r) => r,
        Err(_) => return,
    };
    let op = match record.direction {
        Direction::Upload => Op::Upload,
        Direction::Download => Op::Download,
    };
    if authorizer.check(identity, op, &record.remote_path).is_err() {
        return;
    }
    let _ = cancel_transfer_m3(backend, store.clone(), c.transfer_id).await;
    let _ = TransferStatus::Cancelled;
}
