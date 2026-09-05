//! Message catalog and payload codecs for M1 (`PROTOCOL.md` §4).
//!
//! M1 ships:
//!   - `HELLO` / `HELLO_ACK` — version + capability negotiation.
//!   - `PING` / `PONG` — round-trip test (the M1 exit test).
//!   - `BYE` — clean session close.
//!   - `ERROR` — wire error reporting.
//!
//! All other message types (`TRANSFER_*`, `MANIFEST_*`, `INVENTORY_HINT`,
//! `CHUNK_*`, etc.) are reserved for later milestones. The constants are
//! already named so a future message lands in the right place.

use bytes::Bytes;

use crate::error::ProtocolError;
use crate::protocol::capabilities::{Capabilities, Capability};
use crate::protocol::error::{ErrorCode, ErrorDetail};
use crate::protocol::limits::PROTOCOL_VERSION;
use crate::protocol::varint;
use crate::util::Hash;
use crate::util::TransferId;

// ---------------------------------------------------------------------------
// Message type constants (PROTOCOL.md §4). Re-exported for ergonomic use.
// ---------------------------------------------------------------------------

/// `HELLO` (client → server).
pub const HELLO: u8 = 0x01;
/// `HELLO_ACK` (server → client).
pub const HELLO_ACK: u8 = 0x02;
/// `AUTH` (client → server). Reserved in M1 (no body sent).
pub const AUTH: u8 = 0x03;
/// `AUTH_OK` (server → client). Reserved in M1.
pub const AUTH_OK: u8 = 0x04;
/// `SESSION_INIT` (client → server).
pub const SESSION_INIT: u8 = 0x05;
/// `PING` / `PONG`. Same type id; direction and nonce disambiguate.
pub const PING: u8 = 0x06;
/// `PONG` shares `PING`'s type id; declared for documentation.
pub const PONG: u8 = 0x06;
/// `BYE`.
pub const BYE: u8 = 0x07;
/// Reserved transfer-lifecycle messages (M2+).
#[allow(dead_code)]
pub const TRANSFER_CREATE: u8 = 0x10;
#[allow(dead_code)]
pub const TRANSFER_CREATED: u8 = 0x11;
#[allow(dead_code)]
pub const TRANSFER_PLAN: u8 = 0x12;
#[allow(dead_code)]
pub const TRANSFER_BEGIN: u8 = 0x13;
#[allow(dead_code)]
pub const CHECKPOINT: u8 = 0x14;
#[allow(dead_code)]
pub const VERIFY: u8 = 0x15;
#[allow(dead_code)]
pub const VERIFY_RESULT: u8 = 0x16;
#[allow(dead_code)]
pub const COMMIT: u8 = 0x17;
#[allow(dead_code)]
pub const COMMITTED: u8 = 0x18;
#[allow(dead_code)]
pub const RESUME: u8 = 0x19;
#[allow(dead_code)]
pub const RESUME_STATE: u8 = 0x1A;
#[allow(dead_code)]
pub const CANCEL: u8 = 0x1B;
#[allow(dead_code)]
pub const STAT: u8 = 0x1C;
#[allow(dead_code)]
pub const STAT_RESULT: u8 = 0x1D;
#[allow(dead_code)]
pub const LIST: u8 = 0x1E;
#[allow(dead_code)]
pub const LIST_RESULT: u8 = 0x1F;
/// Reserved metadata messages (M5+).
#[allow(dead_code)]
pub const MANIFEST_BEGIN: u8 = 0x30;
#[allow(dead_code)]
pub const MANIFEST_BATCH: u8 = 0x31;
#[allow(dead_code)]
pub const MANIFEST_END: u8 = 0x32;
#[allow(dead_code)]
pub const INVENTORY_HINT: u8 = 0x33;
#[allow(dead_code)]
pub const CHUNK_QUERY: u8 = 0x34;
#[allow(dead_code)]
pub const CHUNK_RESPONSE: u8 = 0x35;
/// `ERROR`.
pub const ERROR: u8 = 0x7F;

/// Default agent string (re-exported from limits for convenience).
pub use crate::protocol::limits::AGENT_STRING as AGENT;

/// `Pong` is a wire-level alias of `Ping` (same type id 0x06). Re-exported
/// for symmetry with the spec's terminology.
pub type Pong = Ping;

// ---------------------------------------------------------------------------
// Server-side limits (HELLO_ACK)
// ---------------------------------------------------------------------------

/// Server-side limits advertised in `HELLO_ACK` (a strict subset of
/// `OPERATIONS.md` §4 — the items the client must know to size its
/// outbound frames).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum control/metadata payload size, bytes.
    pub max_message_size: u64,
    /// Maximum chunk size, bytes.
    pub max_chunk_size: u64,
    /// Maximum entries per manifest.
    pub max_manifest_entries: u64,
    /// Maximum concurrent data streams per connection.
    pub max_concurrent_streams: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_size: crate::protocol::limits::MAX_MESSAGE_SIZE,
            max_chunk_size: crate::protocol::limits::MAX_CHUNK_SIZE,
            max_manifest_entries: crate::protocol::limits::MAX_MANIFEST_ENTRIES,
            max_concurrent_streams: 32,
        }
    }
}

// ---------------------------------------------------------------------------
// HELLO
// ---------------------------------------------------------------------------

/// `HELLO` payload.
///
/// Wire layout:
/// ```text
/// versions:        u8 count + u8 × count
/// capabilities:    u32 LE
/// agent:           varint length + UTF-8 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Protocol versions the client supports, in preference order. M1
    /// always sends `vec![PROTOCOL_VERSION]`.
    pub versions: Vec<u8>,
    /// Client capabilities bitset.
    pub capabilities: Capabilities,
    /// Free-form client agent string for logs.
    pub agent: String,
}

impl Hello {
    /// Build the default M1 HELLO.
    pub fn default_client() -> Self {
        let mut caps = Capabilities::EMPTY;
        caps.set(Capability::FixedChunking);
        caps.set(Capability::CdcChunking);
        caps.set(Capability::Blake3);
        caps.set(Capability::CompressionZstd);
        caps.set(Capability::SparseFiles);
        caps.set(Capability::Symlinks);
        caps.set(Capability::Hardlinks);
        Self {
            versions: vec![PROTOCOL_VERSION],
            capabilities: caps,
            agent: AGENT.to_string(),
        }
    }

    /// Encode the payload to bytes.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let agent_bytes = self.agent.as_bytes();
        if agent_bytes.len() > u16::MAX as usize {
            return Err(ProtocolError::Malformed("agent too long"));
        }
        if self.versions.len() > u8::MAX as usize {
            return Err(ProtocolError::Malformed("too many versions"));
        }
        let mut out = Vec::with_capacity(1 + self.versions.len() + 4 + 2 + agent_bytes.len());
        out.push(self.versions.len() as u8);
        out.extend_from_slice(&self.versions);
        out.extend_from_slice(&self.capabilities.to_wire().to_le_bytes());
        let mut alen = [0u8; 10];
        let n = varint::encode_varint(agent_bytes.len() as u64, &mut alen);
        out.extend_from_slice(&alen[..n]);
        out.extend_from_slice(agent_bytes);
        Ok(Bytes::from(out))
    }

    /// Decode the payload from `buf`. Bounds checks every length before
    /// allocation, per `PROTOCOL.md` §3.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.is_empty() {
            return Err(ProtocolError::Malformed("HELLO: empty"));
        }
        let count = buf[0] as usize;
        if buf.len() < 1 + count {
            return Err(ProtocolError::Malformed("HELLO: truncated versions"));
        }
        let mut i = 1 + count;
        if buf.len() < i + 4 {
            return Err(ProtocolError::Malformed("HELLO: truncated capabilities"));
        }
        let mut versions = Vec::with_capacity(count);
        versions.extend_from_slice(&buf[1..1 + count]);
        let caps_raw = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let capabilities = Capabilities::from_wire(caps_raw);
        i += 4;
        let (agent_len, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        let agent_len_us: usize = agent_len
            .try_into()
            .map_err(|_| ProtocolError::Malformed("HELLO: agent_len too large"))?;
        if buf.len() < i + agent_len_us {
            return Err(ProtocolError::Malformed("HELLO: truncated agent"));
        }
        let agent = std::str::from_utf8(&buf[i..i + agent_len_us])
            .map_err(|_| ProtocolError::Malformed("HELLO: agent not UTF-8"))?
            .to_string();
        Ok(Self {
            versions,
            capabilities,
            agent,
        })
    }
}

// ---------------------------------------------------------------------------
// HELLO_ACK
// ---------------------------------------------------------------------------

/// `HELLO_ACK` payload.
///
/// Wire layout:
/// ```text
/// version:         u8
/// capabilities:    u32 LE
/// limits:          {u64×3 LE, u32×1 LE}
///                  (max_message_size, max_chunk_size, max_manifest_entries,
///                   max_concurrent_streams)
/// agent:           varint length + UTF-8 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    /// Chosen protocol version. M1 is always `PROTOCOL_VERSION`.
    pub version: u8,
    /// Negotiated capability intersection.
    pub capabilities: Capabilities,
    /// Server-side limits the client must respect.
    pub limits: Limits,
    /// Server agent string.
    pub agent: String,
}

impl HelloAck {
    /// Encode the payload to bytes.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let agent_bytes = self.agent.as_bytes();
        if agent_bytes.len() > u16::MAX as usize {
            return Err(ProtocolError::Malformed("agent too long"));
        }
        let mut out = Vec::with_capacity(1 + 4 + 8 * 3 + 4 + 2 + agent_bytes.len());
        out.push(self.version);
        out.extend_from_slice(&self.capabilities.to_wire().to_le_bytes());
        out.extend_from_slice(&self.limits.max_message_size.to_le_bytes());
        out.extend_from_slice(&self.limits.max_chunk_size.to_le_bytes());
        out.extend_from_slice(&self.limits.max_manifest_entries.to_le_bytes());
        out.extend_from_slice(&self.limits.max_concurrent_streams.to_le_bytes());
        let mut alen = [0u8; 10];
        let n = varint::encode_varint(agent_bytes.len() as u64, &mut alen);
        out.extend_from_slice(&alen[..n]);
        out.extend_from_slice(agent_bytes);
        Ok(Bytes::from(out))
    }

    /// Decode the payload from `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        // 1 + 4 + 8*3 + 4 = 33 bytes minimum
        if buf.len() < 1 + 4 + 8 * 3 + 4 {
            return Err(ProtocolError::Malformed("HELLO_ACK: truncated"));
        }
        let version = buf[0];
        let mut i = 1;
        let caps_raw = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let capabilities = Capabilities::from_wire(caps_raw);
        i += 4;
        let max_message_size = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let max_chunk_size = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let max_manifest_entries = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let max_concurrent_streams = u32::from_le_bytes(buf[i..i + 4].try_into().unwrap());
        i += 4;
        let (agent_len, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        let agent_len_us: usize = agent_len
            .try_into()
            .map_err(|_| ProtocolError::Malformed("HELLO_ACK: agent_len too large"))?;
        if buf.len() < i + agent_len_us {
            return Err(ProtocolError::Malformed("HELLO_ACK: truncated agent"));
        }
        let agent = std::str::from_utf8(&buf[i..i + agent_len_us])
            .map_err(|_| ProtocolError::Malformed("HELLO_ACK: agent not UTF-8"))?
            .to_string();
        Ok(Self {
            version,
            capabilities,
            limits: Limits {
                max_message_size,
                max_chunk_size,
                max_manifest_entries,
                max_concurrent_streams,
            },
            agent,
        })
    }
}

// ---------------------------------------------------------------------------
// PING / PONG
// ---------------------------------------------------------------------------

/// `PING` / `PONG` payload.
///
/// Wire layout:
/// ```text
/// nonce:           u64 LE
/// sender_ts_ms:    u64 LE  (sender's monotonic ms clock)
/// ```
///
/// The PONG echoes the nonce and may overwrite `sender_ts_ms` with the
/// receiver's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    /// Echoed verbatim by the responder.
    pub nonce: u64,
    /// Sender timestamp in milliseconds (wall clock is fine for M1; for M2
    /// this becomes the QUIC connection's monotonic clock).
    pub sender_ts_ms: u64,
}

impl Ping {
    /// Encode to 16 bytes.
    pub fn encode(&self) -> Bytes {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.nonce.to_le_bytes());
        out[8..].copy_from_slice(&self.sender_ts_ms.to_le_bytes());
        Bytes::copy_from_slice(&out)
    }

    /// Decode from 16 bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 {
            return Err(ProtocolError::Malformed("PING: truncated"));
        }
        let nonce = u64::from_le_bytes(buf[..8].try_into().unwrap());
        let sender_ts_ms = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        Ok(Self { nonce, sender_ts_ms })
    }
}

// ---------------------------------------------------------------------------
// BYE
// ---------------------------------------------------------------------------

/// `BYE` payload: a u32 reason code (`ErrorCode` by convention, but not
/// enforced — the field is informational; semantics come from the code
/// table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bye {
    /// Reason code (informational; `ErrorCode` is the canonical set).
    pub code: u32,
}

impl Bye {
    /// Encode as 4 bytes LE.
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&self.code.to_le_bytes())
    }

    /// Decode from 4 bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 4 {
            return Err(ProtocolError::Malformed("BYE: truncated"));
        }
        let code = u32::from_le_bytes(buf[..4].try_into().unwrap());
        Ok(Self { code })
    }
}

// ---------------------------------------------------------------------------
// ERROR
// ---------------------------------------------------------------------------

/// `ERROR` payload.
///
/// Wire layout:
/// ```text
/// code:            u32 LE
/// retryable:       u8  (0 or 1)
/// detail_len:      varint
/// detail:          UTF-8 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMsg {
    /// Error code from `ErrorCode`.
    pub code: ErrorCode,
    /// Whether the caller should retry.
    pub retryable: bool,
    /// Non-sensitive detail (capped at `MAX_ERROR_DETAIL`).
    pub detail: ErrorDetail,
}

impl ErrorMsg {
    /// Construct from a code and a detail. Retryability is pulled from
    /// `ErrorCode::retryable()`.
    pub fn new(code: ErrorCode, detail: impl Into<ErrorDetail>) -> Self {
        let detail = detail.into();
        let retryable = code.retryable();
        Self { code, retryable, detail }
    }

    /// Encode the payload.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let detail_bytes = self.detail.as_str().as_bytes();
        let mut out = Vec::with_capacity(4 + 1 + 2 + detail_bytes.len());
        out.extend_from_slice(&self.code.to_wire().to_le_bytes());
        out.push(self.retryable as u8);
        let mut dlen = [0u8; 10];
        let n = varint::encode_varint(detail_bytes.len() as u64, &mut dlen);
        out.extend_from_slice(&dlen[..n]);
        out.extend_from_slice(detail_bytes);
        Ok(Bytes::from(out))
    }

    /// Decode the payload.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 4 + 1 {
            return Err(ProtocolError::Malformed("ERROR: truncated header"));
        }
        let code = ErrorCode::from_wire(u32::from_le_bytes(buf[..4].try_into().unwrap()));
        let retryable = match buf[4] {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::Malformed("ERROR: retryable not 0/1")),
        };
        let (dlen, consumed) = varint::decode_varint(&buf[5..])?;
        let i = 5 + consumed;
        let dlen_us: usize = dlen
            .try_into()
            .map_err(|_| ProtocolError::Malformed("ERROR: detail_len too large"))?;
        if buf.len() < i + dlen_us {
            return Err(ProtocolError::Malformed("ERROR: truncated detail"));
        }
        let detail_str = std::str::from_utf8(&buf[i..i + dlen_us])
            .map_err(|_| ProtocolError::Malformed("ERROR: detail not UTF-8"))?
            .to_string();
        Ok(Self {
            code,
            retryable,
            detail: ErrorDetail(detail_str),
        })
    }
}

// ---------------------------------------------------------------------------
// SESSION_INIT
// ---------------------------------------------------------------------------

/// `SESSION_INIT` payload. Used by the client to request per-session
/// options after AUTH_OK. M1 ships a minimal shape; expanded in M2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionOptions {
    /// Requested bandwidth cap in bytes/sec. `0` = no cap.
    pub bandwidth_bps: u64,
    /// Priority hint. Higher = more important. Reserved; M1 ignores.
    pub priority: u16,
}

impl SessionOptions {
    /// Encode as 10 bytes (8 + 2).
    pub fn encode(&self) -> Bytes {
        let mut out = [0u8; 10];
        out[..8].copy_from_slice(&self.bandwidth_bps.to_le_bytes());
        out[8..10].copy_from_slice(&self.priority.to_le_bytes());
        Bytes::copy_from_slice(&out)
    }

    /// Decode from 10 bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 10 {
            return Err(ProtocolError::Malformed("SESSION_INIT: truncated"));
        }
        let bandwidth_bps = u64::from_le_bytes(buf[..8].try_into().unwrap());
        let priority = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        Ok(Self { bandwidth_bps, priority })
    }
}

/// Alias matching the spec's name for the SESSION_INIT payload struct.
pub type SessionInit = SessionOptions;

// ---------------------------------------------------------------------------
// TRANSFER_CREATE
// ---------------------------------------------------------------------------

/// Op code carried in `TRANSFER_CREATE` (`PROTOCOL.md` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferOp {
    /// Single-file upload.
    Upload = 1,
    /// Single-file download.
    Download = 2,
}

impl TransferOp {
    /// Decode from the wire byte. Unknown codes are rejected.
    pub fn from_wire(b: u8) -> Result<Self, ProtocolError> {
        match b {
            1 => Ok(Self::Upload),
            2 => Ok(Self::Download),
            _ => Err(ProtocolError::Malformed("TRANSFER_CREATE: unknown op")),
        }
    }
    /// Encode to the wire byte.
    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

/// `TRANSFER_CREATE` payload (client → server).
///
/// Wire layout (`PROTOCOL.md` §4):
/// ```text
/// op:                 u8
/// reserved:           7 bytes (zero)
/// src_path_len:       varint
/// src_path:           UTF-8 bytes
/// dst_path_len:       varint
/// dst_path:           UTF-8 bytes
/// idempotency_len:    varint
/// idempotency_key:    UTF-8 bytes
/// file_size:          u64 LE
/// file_hash:          32 bytes (whole-file BLAKE3)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCreate {
    pub op: TransferOp,
    /// Source path on the *client* (empty for download).
    pub src_path: String,
    /// Destination path on the *server*. The server validates it as a `VPath`.
    pub dst_path: String,
    /// Client-supplied idempotency key (`PROTOCOL.md` §8).
    pub idempotency_key: String,
    /// Total expected file size in bytes (u64).
    pub file_size: u64,
    /// Whole-file BLAKE3 of the source.
    pub file_hash: Hash,
}

impl TransferCreate {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let sp = self.src_path.as_bytes();
        let dp = self.dst_path.as_bytes();
        let id = self.idempotency_key.as_bytes();
        if sp.len() > u16::MAX as usize || dp.len() > u16::MAX as usize || id.len() > u16::MAX as usize {
            return Err(ProtocolError::Malformed("TRANSFER_CREATE: field too long"));
        }
        let mut out = Vec::with_capacity(8 + 3 * 10 + sp.len() + dp.len() + id.len() + 8 + 32);
        out.push(self.op.to_wire());
        out.extend_from_slice(&[0u8; 7]);
        let mut v = [0u8; 10];
        let n = varint::encode_varint(sp.len() as u64, &mut v);
        out.extend_from_slice(&v[..n]);
        out.extend_from_slice(sp);
        let n = varint::encode_varint(dp.len() as u64, &mut v);
        out.extend_from_slice(&v[..n]);
        out.extend_from_slice(dp);
        let n = varint::encode_varint(id.len() as u64, &mut v);
        out.extend_from_slice(&v[..n]);
        out.extend_from_slice(id);
        out.extend_from_slice(&self.file_size.to_le_bytes());
        out.extend_from_slice(self.file_hash.as_bytes());
        Ok(Bytes::from(out))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 8 + 8 + 32 {
            return Err(ProtocolError::Malformed("TRANSFER_CREATE: truncated"));
        }
        let op = TransferOp::from_wire(buf[0])?;
        let mut i = 8;
        let (sp_len, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        let sp_len_us: usize = sp_len
            .try_into()
            .map_err(|_| ProtocolError::Malformed("TRANSFER_CREATE: src_path_len too large"))?;
        if buf.len() < i + sp_len_us {
            return Err(ProtocolError::Malformed("TRANSFER_CREATE: truncated src_path"));
        }
        let src_path = std::str::from_utf8(&buf[i..i + sp_len_us])
            .map_err(|_| ProtocolError::Malformed("TRANSFER_CREATE: src_path not UTF-8"))?
            .to_string();
        i += sp_len_us;
        let (dp_len, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        let dp_len_us: usize = dp_len
            .try_into()
            .map_err(|_| ProtocolError::Malformed("TRANSFER_CREATE: dst_path_len too large"))?;
        if buf.len() < i + dp_len_us {
            return Err(ProtocolError::Malformed("TRANSFER_CREATE: truncated dst_path"));
        }
        let dst_path = std::str::from_utf8(&buf[i..i + dp_len_us])
            .map_err(|_| ProtocolError::Malformed("TRANSFER_CREATE: dst_path not UTF-8"))?
            .to_string();
        i += dp_len_us;
        let (id_len, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        let id_len_us: usize = id_len
            .try_into()
            .map_err(|_| ProtocolError::Malformed("TRANSFER_CREATE: idempotency_len too large"))?;
        if buf.len() < i + id_len_us + 8 + 32 {
            return Err(ProtocolError::Malformed("TRANSFER_CREATE: truncated tail"));
        }
        let idempotency_key = std::str::from_utf8(&buf[i..i + id_len_us])
            .map_err(|_| ProtocolError::Malformed("TRANSFER_CREATE: idempotency not UTF-8"))?
            .to_string();
        i += id_len_us;
        let file_size = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let file_hash = Hash::from_bytes(&buf[i..i + 32])
            .ok_or_else(|| ProtocolError::Malformed("TRANSFER_CREATE: bad hash"))?;
        Ok(Self { op, src_path, dst_path, idempotency_key, file_size, file_hash })
    }
}

// ---------------------------------------------------------------------------
// TRANSFER_CREATED
// ---------------------------------------------------------------------------

/// `TRANSFER_CREATED` payload (server → client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferCreated {
    /// Server-assigned 16-byte ULID.
    pub transfer_id: TransferId,
    /// True if the idempotency key matched an existing transfer. M2 always
    /// reports `false`; M3 owns resume.
    pub resumed: bool,
    /// Maximum chunk size the server will accept on data streams, in bytes.
    pub max_chunk_size: u64,
}

impl TransferCreated {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 1 + 7 + 8);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.push(self.resumed as u8);
        out.extend_from_slice(&[0u8; 7]);
        out.extend_from_slice(&self.max_chunk_size.to_le_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 1 + 7 + 8 {
            return Err(ProtocolError::Malformed("TRANSFER_CREATED: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("TRANSFER_CREATED: bad transfer_id"))?;
        let resumed = match buf[16] {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::Malformed("TRANSFER_CREATED: bad resumed")),
        };
        let i = 16 + 1 + 7;
        let max_chunk_size = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        Ok(Self { transfer_id, resumed, max_chunk_size })
    }
}

// ---------------------------------------------------------------------------
// TRANSFER_PLAN
// ---------------------------------------------------------------------------

/// `TRANSFER_PLAN` payload (server → client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferPlan {
    pub transfer_id: TransferId,
    pub bytes_total: u64,
    /// Bytes the sender must transmit. Equals `bytes_total` for a full transfer
    /// in M2; delta lands with M7.
    pub bytes_to_transfer: u64,
    /// Bytes reused from the destination's existing copy (delta). Always 0 in M2.
    pub bytes_reusable: u64,
}

impl TransferPlan {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 8 * 3);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(&self.bytes_total.to_le_bytes());
        out.extend_from_slice(&self.bytes_to_transfer.to_le_bytes());
        out.extend_from_slice(&self.bytes_reusable.to_le_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 8 * 3 {
            return Err(ProtocolError::Malformed("TRANSFER_PLAN: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("TRANSFER_PLAN: bad transfer_id"))?;
        let mut i = 16;
        let bytes_total = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let bytes_to_transfer = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let bytes_reusable = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        Ok(Self { transfer_id, bytes_total, bytes_to_transfer, bytes_reusable })
    }
}

// ---------------------------------------------------------------------------
// TRANSFER_BEGIN
// ---------------------------------------------------------------------------

/// `TRANSFER_BEGIN` payload (client → server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferBegin {
    pub transfer_id: TransferId,
}

impl TransferBegin {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(self.transfer_id.as_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 {
            return Err(ProtocolError::Malformed("TRANSFER_BEGIN: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("TRANSFER_BEGIN: bad transfer_id"))?;
        Ok(Self { transfer_id })
    }
}

// ---------------------------------------------------------------------------
// VERIFY / VERIFY_RESULT
// ---------------------------------------------------------------------------

/// `VERIFY` payload (sender → receiver).
///
/// The sender asks the receiver to confirm that the staged file's whole-file
/// BLAKE3 matches `expected_hash`. The receiver streams the staged file
/// through a BLAKE3 hasher and replies with [`VerifyResult`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verify {
    pub transfer_id: TransferId,
    /// Whole-file BLAKE3 the sender expects.
    pub expected_hash: Hash,
}

impl Verify {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 32);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(self.expected_hash.as_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 32 {
            return Err(ProtocolError::Malformed("VERIFY: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("VERIFY: bad transfer_id"))?;
        let expected_hash = Hash::from_bytes(&buf[16..16 + 32])
            .ok_or_else(|| ProtocolError::Malformed("VERIFY: bad hash"))?;
        Ok(Self { transfer_id, expected_hash })
    }
}

/// `VERIFY_RESULT` payload (receiver → sender).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult {
    pub transfer_id: TransferId,
    /// True iff the whole-file hash matches.
    pub ok: bool,
    /// The hash the receiver actually computed. Always populated.
    pub computed_hash: Hash,
}

impl VerifyResult {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 1 + 7 + 32);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.push(self.ok as u8);
        out.extend_from_slice(&[0u8; 7]);
        out.extend_from_slice(self.computed_hash.as_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 1 + 7 + 32 {
            return Err(ProtocolError::Malformed("VERIFY_RESULT: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("VERIFY_RESULT: bad transfer_id"))?;
        let ok = match buf[16] {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::Malformed("VERIFY_RESULT: bad ok")),
        };
        let i = 16 + 1 + 7;
        let computed_hash = Hash::from_bytes(&buf[i..i + 32])
            .ok_or_else(|| ProtocolError::Malformed("VERIFY_RESULT: bad hash"))?;
        Ok(Self { transfer_id, ok, computed_hash })
    }
}

// ---------------------------------------------------------------------------
// COMMIT / COMMITTED
// ---------------------------------------------------------------------------

/// `COMMIT` payload (sender → receiver). Tells the receiver to atomically
/// rename the staged file into its final path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commit {
    pub transfer_id: TransferId,
}

impl Commit {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(self.transfer_id.as_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 {
            return Err(ProtocolError::Malformed("COMMIT: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("COMMIT: bad transfer_id"))?;
        Ok(Self { transfer_id })
    }
}

/// `COMMITTED` payload (receiver → sender).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    pub transfer_id: TransferId,
    /// Number of files committed (always 1 in M2).
    pub files: u32,
}

impl Committed {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 4);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(&self.files.to_le_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 4 {
            return Err(ProtocolError::Malformed("COMMITTED: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("COMMITTED: bad transfer_id"))?;
        let files = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        Ok(Self { transfer_id, files })
    }
}

// ---------------------------------------------------------------------------
// Top-level Message enum
// ---------------------------------------------------------------------------

/// A decoded, typed message body. The frame header has already been parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `HELLO`.
    Hello(Hello),
    /// `HELLO_ACK`.
    HelloAck(HelloAck),
    /// `PING` (client → server).
    Ping(Ping),
    /// `PONG` (server → client). Identical wire form to PING.
    Pong(Ping),
    /// `SESSION_INIT`.
    SessionInit(SessionOptions),
    /// `BYE`.
    Bye(Bye),
    /// `ERROR`.
    Error(ErrorMsg),
    /// `TRANSFER_CREATE` (client → server).
    TransferCreate(TransferCreate),
    /// `TRANSFER_CREATED` (server → client).
    TransferCreated(TransferCreated),
    /// `TRANSFER_PLAN` (server → client).
    TransferPlan(TransferPlan),
    /// `TRANSFER_BEGIN` (client → server).
    TransferBegin(TransferBegin),
    /// `VERIFY` (sender → receiver).
    Verify(Verify),
    /// `VERIFY_RESULT` (receiver → sender).
    VerifyResult(VerifyResult),
    /// `COMMIT` (sender → receiver).
    Commit(Commit),
    /// `COMMITTED` (receiver → sender).
    Committed(Committed),
}

impl Message {
    /// Return the wire type byte for this message.
    pub fn type_byte(&self) -> u8 {
        match self {
            Message::Hello(_) => HELLO,
            Message::HelloAck(_) => HELLO_ACK,
            Message::Ping(_) | Message::Pong(_) => PING,
            Message::SessionInit(_) => SESSION_INIT,
            Message::Bye(_) => BYE,
            Message::Error(_) => ERROR,
            Message::TransferCreate(_) => TRANSFER_CREATE,
            Message::TransferCreated(_) => TRANSFER_CREATED,
            Message::TransferPlan(_) => TRANSFER_PLAN,
            Message::TransferBegin(_) => TRANSFER_BEGIN,
            Message::Verify(_) => VERIFY,
            Message::VerifyResult(_) => VERIFY_RESULT,
            Message::Commit(_) => COMMIT,
            Message::Committed(_) => COMMITTED,
        }
    }

    /// Encode the payload (no frame header). Returns `(type_byte, payload)`.
    pub fn encode(&self) -> Result<(u8, Bytes), ProtocolError> {
        match self {
            Message::Hello(h) => Ok((HELLO, h.encode()?)),
            Message::HelloAck(h) => Ok((HELLO_ACK, h.encode()?)),
            Message::Ping(p) => Ok((PING, p.encode())),
            Message::Pong(p) => Ok((PING, p.encode())),
            Message::SessionInit(s) => Ok((SESSION_INIT, s.encode())),
            Message::Bye(b) => Ok((BYE, b.encode())),
            Message::Error(e) => Ok((ERROR, e.encode()?)),
            Message::TransferCreate(m) => Ok((TRANSFER_CREATE, m.encode()?)),
            Message::TransferCreated(m) => Ok((TRANSFER_CREATED, m.encode()?)),
            Message::TransferPlan(m) => Ok((TRANSFER_PLAN, m.encode()?)),
            Message::TransferBegin(m) => Ok((TRANSFER_BEGIN, m.encode()?)),
            Message::Verify(m) => Ok((VERIFY, m.encode()?)),
            Message::VerifyResult(m) => Ok((VERIFY_RESULT, m.encode()?)),
            Message::Commit(m) => Ok((COMMIT, m.encode()?)),
            Message::Committed(m) => Ok((COMMITTED, m.encode()?)),
        }
    }

    /// Decode a typed message from a frame's `type_byte` and `payload`.
    pub fn decode(type_byte: u8, payload: &[u8]) -> Result<Self, ProtocolError> {
        match type_byte {
            HELLO => Ok(Message::Hello(Hello::decode(payload)?)),
            HELLO_ACK => Ok(Message::HelloAck(HelloAck::decode(payload)?)),
            PING => Ok(Message::Ping(Ping::decode(payload)?)),
            SESSION_INIT => Ok(Message::SessionInit(SessionOptions::decode(payload)?)),
            BYE => Ok(Message::Bye(Bye::decode(payload)?)),
            ERROR => Ok(Message::Error(ErrorMsg::decode(payload)?)),
            TRANSFER_CREATE => Ok(Message::TransferCreate(TransferCreate::decode(payload)?)),
            TRANSFER_CREATED => Ok(Message::TransferCreated(TransferCreated::decode(payload)?)),
            TRANSFER_PLAN => Ok(Message::TransferPlan(TransferPlan::decode(payload)?)),
            TRANSFER_BEGIN => Ok(Message::TransferBegin(TransferBegin::decode(payload)?)),
            VERIFY => Ok(Message::Verify(Verify::decode(payload)?)),
            VERIFY_RESULT => Ok(Message::VerifyResult(VerifyResult::decode(payload)?)),
            COMMIT => Ok(Message::Commit(Commit::decode(payload)?)),
            COMMITTED => Ok(Message::Committed(Committed::decode(payload)?)),
            // PONG and HELLO share type ids with PING and HELLO; they are
            // produced by the encode side. We never receive PONG on the
            // server or PING on the client as PONG; the direction is
            // established by the call site (server side treats PING-type
            // as PING; client side treats it as PONG by context).
            other => Err(ProtocolError::UnsupportedMessage(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let h = Hello::default_client();
        let p = h.encode().unwrap();
        let h2 = Hello::decode(&p).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn hello_ack_roundtrip() {
        let h = HelloAck {
            version: PROTOCOL_VERSION,
            capabilities: Capabilities::EMPTY,
            limits: Limits::default(),
            agent: "velcruxd/0.1".into(),
        };
        let p = h.encode().unwrap();
        let h2 = HelloAck::decode(&p).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn ping_roundtrip() {
        let p = Ping { nonce: 0xDEAD_BEEF, sender_ts_ms: 1234 };
        let buf = p.encode();
        let p2 = Ping::decode(&buf).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn error_roundtrip() {
        let e = ErrorMsg::new(ErrorCode::ChecksumMismatch, ErrorDetail::new("bad chunk"));
        let buf = e.encode().unwrap();
        let e2 = ErrorMsg::decode(&buf).unwrap();
        assert_eq!(e, e2);
    }

    #[test]
    fn bye_roundtrip() {
        let b = Bye { code: ErrorCode::TransferCancelled.to_wire() };
        let buf = b.encode();
        let b2 = Bye::decode(&buf).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn session_init_roundtrip() {
        let s = SessionOptions { bandwidth_bps: 1_000_000, priority: 7 };
        let buf = s.encode();
        let s2 = SessionOptions::decode(&buf).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn message_enum_hello_roundtrip() {
        let m = Message::Hello(Hello::default_client());
        let (tb, p) = m.encode().unwrap();
        assert_eq!(tb, HELLO);
        let m2 = Message::decode(tb, &p).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn rejects_truncated_hello() {
        let e = Hello::decode(&[0x01]).unwrap_err();
        assert!(matches!(e, ProtocolError::Malformed(_)));
    }

    #[test]
    fn rejects_overlong_agent() {
        let mut h = Hello::default_client();
        h.agent = "x".repeat(70_000);
        let e = h.encode().unwrap_err();
        assert!(matches!(e, ProtocolError::Malformed(_)));
    }

    #[test]
    fn transfer_op_roundtrip() {
        assert_eq!(TransferOp::from_wire(1).unwrap(), TransferOp::Upload);
        assert_eq!(TransferOp::from_wire(2).unwrap(), TransferOp::Download);
        assert!(TransferOp::from_wire(0).is_err());
        assert!(TransferOp::from_wire(99).is_err());
    }

    #[test]
    fn transfer_create_roundtrip() {
        let m = TransferCreate {
            op: TransferOp::Upload,
            src_path: "local/foo.bin".into(),
            dst_path: "data/foo.bin".into(),
            idempotency_key: "abc-123".into(),
            file_size: 12345,
            file_hash: Hash::of(b"hello"),
        };
        let buf = m.encode().unwrap();
        let m2 = TransferCreate::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn transfer_create_rejects_truncated() {
        let m = TransferCreate {
            op: TransferOp::Download,
            src_path: "".into(),
            dst_path: "data/x".into(),
            idempotency_key: "k".into(),
            file_size: 0,
            file_hash: Hash::ZERO,
        };
        let buf = m.encode().unwrap();
        let mut bad = buf.to_vec();
        bad.pop();
        assert!(TransferCreate::decode(&bad).is_err());
    }

    #[test]
    fn transfer_created_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let m = TransferCreated {
            transfer_id: tid,
            resumed: false,
            max_chunk_size: 4 * 1024 * 1024,
        };
        let buf = m.encode().unwrap();
        let m2 = TransferCreated::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn transfer_plan_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let m = TransferPlan {
            transfer_id: tid,
            bytes_total: 100,
            bytes_to_transfer: 100,
            bytes_reusable: 0,
        };
        let buf = m.encode().unwrap();
        let m2 = TransferPlan::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn transfer_begin_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let m = TransferBegin { transfer_id: tid };
        let buf = m.encode().unwrap();
        let m2 = TransferBegin::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn verify_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let m = Verify { transfer_id: tid, expected_hash: Hash::of(b"x") };
        let buf = m.encode().unwrap();
        let m2 = Verify::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn verify_result_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let m = VerifyResult { transfer_id: tid, ok: true, computed_hash: Hash::of(b"x") };
        let buf = m.encode().unwrap();
        let m2 = VerifyResult::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn commit_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let m = Commit { transfer_id: tid };
        let buf = m.encode().unwrap();
        let m2 = Commit::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn committed_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let m = Committed { transfer_id: tid, files: 1 };
        let buf = m.encode().unwrap();
        let m2 = Committed::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn message_enum_routes_all_m2_variants() {
        let tid = crate::util::TransferId::generate();
        let cases = vec![
            Message::TransferCreate(TransferCreate {
                op: TransferOp::Upload,
                src_path: "x".into(),
                dst_path: "y".into(),
                idempotency_key: "k".into(),
                file_size: 1,
                file_hash: Hash::ZERO,
            }),
            Message::TransferCreated(TransferCreated {
                transfer_id: tid,
                resumed: false,
                max_chunk_size: 1024,
            }),
            Message::TransferPlan(TransferPlan {
                transfer_id: tid,
                bytes_total: 1,
                bytes_to_transfer: 1,
                bytes_reusable: 0,
            }),
            Message::TransferBegin(TransferBegin { transfer_id: tid }),
            Message::Verify(Verify { transfer_id: tid, expected_hash: Hash::ZERO }),
            Message::VerifyResult(VerifyResult { transfer_id: tid, ok: true, computed_hash: Hash::ZERO }),
            Message::Commit(Commit { transfer_id: tid }),
            Message::Committed(Committed { transfer_id: tid, files: 1 }),
        ];
        for m in cases {
            let (tb, payload) = m.encode().unwrap();
            let m2 = Message::decode(tb, &payload).unwrap();
            assert_eq!(m, m2);
        }
    }
}





