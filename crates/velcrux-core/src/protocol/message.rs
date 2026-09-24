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

use crate::chunking::ChunkParams;
use crate::error::ProtocolError;
use crate::protocol::capabilities::{Capabilities, Capability};
use crate::protocol::error::{ErrorCode, ErrorDetail};
use crate::protocol::limits::{
    MANIFEST_BATCH_SIZE, MAX_MANIFEST_BYTES, MAX_MANIFEST_ENTRIES, PROTOCOL_VERSION,
};
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
// AUTH / AUTH_OK (M4)
// ---------------------------------------------------------------------------

/// `AUTH` mechanism ids (`SECURITY.md` §2). The mechanism is a registry id;
/// mTLS (0) is the MVP default and carries an empty token because the
/// identity is already established by the TLS handshake.
pub const AUTH_MECHANISM_MTLS: u16 = 0;
/// Reserved for SSH-style public-key auth (Ed25519 over the TLS exporter).
/// Not implemented in the MVP; a server that receives it replies
/// `ERROR{AUTH_FAILED}` and closes (`SECURITY.md` §2, §4).
pub const AUTH_MECHANISM_SSH_PUBKEY: u16 = 1;

/// `AUTH` payload (client → server, `PROTOCOL.md` §4).
///
/// Wire layout:
/// ```text
/// mechanism:   u16 LE
/// reserved:    u16 (zero on send, ignored on receive)
/// token_len:   u32 LE  (bounded by MAX_AUTH_TOKEN; 0 for mTLS)
/// token:       bytes
/// ```
///
/// The token is opaque at this layer — its meaning is per-mechanism. For
/// mTLS it is empty: the client certificate presented during the QUIC
/// handshake *is* the credential, and `AUTH` merely completes the session
/// state machine (`PROTOCOL.md` §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// Authentication mechanism id. Unknown mechanisms are rejected at
    /// decode time (fail closed, `SECURITY.md` §1 #5).
    pub mechanism: u16,
    /// Opaque, mechanism-specific token. Bounded by `MAX_AUTH_TOKEN`.
    pub token: Vec<u8>,
}

impl Auth {
    /// Build the mTLS `AUTH` message (empty token).
    pub fn mtls() -> Self {
        Self {
            mechanism: AUTH_MECHANISM_MTLS,
            token: Vec::new(),
        }
    }

    /// Encode the payload to bytes.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        if self.token.len() > crate::protocol::limits::MAX_AUTH_TOKEN {
            return Err(ProtocolError::Malformed("AUTH: token too long"));
        }
        let mut out = Vec::with_capacity(4 + 4 + self.token.len());
        out.extend_from_slice(&self.mechanism.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(self.token.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.token);
        Ok(Bytes::from(out))
    }

    /// Decode the payload from `buf`. Bounds checks every length before
    /// allocation, per `PROTOCOL.md` §3.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        // 2 + 2 + 4 = 8 bytes minimum.
        if buf.len() < 8 {
            return Err(ProtocolError::Malformed("AUTH: truncated"));
        }
        let mechanism = u16::from_le_bytes([buf[0], buf[1]]);
        // reserved = buf[2..4], must be zero on send and is ignored.
        let token_len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if token_len as usize > crate::protocol::limits::MAX_AUTH_TOKEN {
            return Err(ProtocolError::Malformed("AUTH: token too long"));
        }
        let token_len_us = token_len as usize;
        if buf.len() < 8 + token_len_us {
            return Err(ProtocolError::Malformed("AUTH: truncated token"));
        }
        // Fail closed on unknown mechanisms: an AUTH we cannot understand
        // must not be treated as a weaker-but-acceptable request.
        if mechanism != AUTH_MECHANISM_MTLS && mechanism != AUTH_MECHANISM_SSH_PUBKEY {
            return Err(ProtocolError::Malformed("AUTH: unknown mechanism"));
        }
        Ok(Self {
            mechanism,
            token: buf[8..8 + token_len_us].to_vec(),
        })
    }
}

/// `AUTH_OK` payload (server → client, `PROTOCOL.md` §4).
///
/// Wire layout:
/// ```text
/// identity_len:  varint  (bounded by MAX_IDENTITY_LEN)
/// identity:      UTF-8 bytes
/// permissions:   u64 LE bitset (`crate::auth::PermSet::to_wire`)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOk {
    /// Server-verified identity name (SAN URI name or CN fallback,
    /// `SECURITY.md` §2).
    pub identity: String,
    /// Granted permission bitset. Wire form is defined by the `auth`
    /// module; the protocol layer treats it as an opaque u64.
    pub permissions: u64,
}

impl AuthOk {
    /// Encode the payload to bytes.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let ident_bytes = self.identity.as_bytes();
        if ident_bytes.len() > crate::protocol::limits::MAX_IDENTITY_LEN {
            return Err(ProtocolError::Malformed("AUTH_OK: identity too long"));
        }
        let mut out = Vec::with_capacity(10 + ident_bytes.len());
        let mut ilen = [0u8; 10];
        let n = varint::encode_varint(ident_bytes.len() as u64, &mut ilen);
        out.extend_from_slice(&ilen[..n]);
        out.extend_from_slice(ident_bytes);
        out.extend_from_slice(&self.permissions.to_le_bytes());
        Ok(Bytes::from(out))
    }

    /// Decode the payload from `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.is_empty() {
            return Err(ProtocolError::Malformed("AUTH_OK: empty"));
        }
        let (ilen, consumed) = varint::decode_varint(buf)?;
        let i = consumed;
        let ilen_us: usize = ilen
            .try_into()
            .map_err(|_| ProtocolError::Malformed("AUTH_OK: identity_len too large"))?;
        if ilen_us > crate::protocol::limits::MAX_IDENTITY_LEN {
            return Err(ProtocolError::Malformed("AUTH_OK: identity too long"));
        }
        // 8 = permissions bitset at the tail.
        if buf.len() < i + ilen_us + 8 {
            return Err(ProtocolError::Malformed("AUTH_OK: truncated"));
        }
        let identity = std::str::from_utf8(&buf[i..i + ilen_us])
            .map_err(|_| ProtocolError::Malformed("AUTH_OK: identity not UTF-8"))?
            .to_string();
        let off = i + ilen_us;
        let permissions =
            u64::from_le_bytes(buf[off..off + 8].try_into().expect("8 bytes for u64"));
        Ok(Self {
            identity,
            permissions,
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
        Ok(Self {
            nonce,
            sender_ts_ms,
        })
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
        Self {
            code,
            retryable,
            detail,
        }
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
        Ok(Self {
            bandwidth_bps,
            priority,
        })
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
    /// Directory sync upload.
    SyncUpload = 3,
    /// Directory sync download.
    SyncDownload = 4,
    /// File deletion.
    Delete = 5,
}

impl TransferOp {
    /// Decode from the wire byte. Unknown codes are rejected.
    pub fn from_wire(b: u8) -> Result<Self, ProtocolError> {
        match b {
            1 => Ok(Self::Upload),
            2 => Ok(Self::Download),
            3 => Ok(Self::SyncUpload),
            4 => Ok(Self::SyncDownload),
            5 => Ok(Self::Delete),
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
        if sp.len() > u16::MAX as usize
            || dp.len() > u16::MAX as usize
            || id.len() > u16::MAX as usize
        {
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
            return Err(ProtocolError::Malformed(
                "TRANSFER_CREATE: truncated src_path",
            ));
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
            return Err(ProtocolError::Malformed(
                "TRANSFER_CREATE: truncated dst_path",
            ));
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
        Ok(Self {
            op,
            src_path,
            dst_path,
            idempotency_key,
            file_size,
            file_hash,
        })
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
        Ok(Self {
            transfer_id,
            resumed,
            max_chunk_size,
        })
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
        Ok(Self {
            transfer_id,
            bytes_total,
            bytes_to_transfer,
            bytes_reusable,
        })
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
        Ok(Self {
            transfer_id,
            expected_hash,
        })
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
        Ok(Self {
            transfer_id,
            ok,
            computed_hash,
        })
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
// M3: CHECKPOINT / RESUME / RESUME_STATE / CANCEL / STAT / LIST
// ---------------------------------------------------------------------------

use crate::state::MAX_WIRE_CHUNKS;

/// `CHECKPOINT` payload (sender → receiver).
///
/// Sent at most every `CHECKPOINT_BYTES_INTERVAL` (1 GiB) or
/// `CHECKPOINT_TIME_INTERVAL_MS` (10 s), whichever comes first. The
/// receiver uses it to advance its local state DB; it does *not* affect
/// which chunks the sender ships (the wire is still the source of
/// truth), it just gives the receiver a save-now event so a crash
/// between checkpoints loses at most one interval of progress.
///
/// Wire layout:
/// ```text
/// transfer_id:          16 bytes
/// bytes_transferred:    u64 LE
/// verified_up_to:       u64 LE
/// ts_ms:                u64 LE
/// completed_count:      varint
/// completed_chunks:     varint × completed_count
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub transfer_id: TransferId,
    pub bytes_transferred: u64,
    pub verified_up_to: u64,
    pub ts_ms: u64,
    pub completed_chunks: Vec<u64>,
}

impl Checkpoint {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        if self.completed_chunks.len() as u64 > MAX_WIRE_CHUNKS {
            return Err(ProtocolError::Malformed("too many completed chunks"));
        }
        let mut out = Vec::with_capacity(16 + 8 * 3 + 11);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(&self.bytes_transferred.to_le_bytes());
        out.extend_from_slice(&self.verified_up_to.to_le_bytes());
        out.extend_from_slice(&self.ts_ms.to_le_bytes());
        let mut tmp = [0u8; 10];
        let n = varint::encode_varint(self.completed_chunks.len() as u64, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
        for &idx in &self.completed_chunks {
            let n = varint::encode_varint(idx, &mut tmp);
            out.extend_from_slice(&tmp[..n]);
        }
        Ok(Bytes::from(out))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 8 * 3 {
            return Err(ProtocolError::Malformed("CHECKPOINT: truncated header"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("CHECKPOINT: bad transfer_id"))?;
        let mut i = 16;
        let bytes_transferred = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let verified_up_to = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let ts_ms = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let (count, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        if count > MAX_WIRE_CHUNKS {
            return Err(ProtocolError::Malformed("too many completed chunks"));
        }
        let mut completed = Vec::with_capacity(count as usize);
        let mut prev: Option<u64> = None;
        for _ in 0..count {
            if i >= buf.len() {
                return Err(ProtocolError::Malformed("CHECKPOINT: truncated chunks"));
            }
            let (idx, consumed) = varint::decode_varint(&buf[i..])?;
            i += consumed;
            if let Some(p) = prev {
                if idx <= p {
                    return Err(ProtocolError::Malformed("CHECKPOINT: non-monotonic chunks"));
                }
            }
            completed.push(idx);
            prev = Some(idx);
        }
        Ok(Self {
            transfer_id,
            bytes_transferred,
            verified_up_to,
            ts_ms,
            completed_chunks: completed,
        })
    }
}

/// `RESUME` payload (client → server). The client asks the server to
/// return the saved `RESUME_STATE` for a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resume {
    pub transfer_id: TransferId,
    /// Idempotency key. UNIQUE per role; the server uses (role, key)
    /// to find the canonical state row.
    pub idempotency_key: String,
}

impl Resume {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let key = self.idempotency_key.as_bytes();
        if key.len() > u16::MAX as usize {
            return Err(ProtocolError::Malformed("RESUME: idempotency_key too long"));
        }
        let mut out = Vec::with_capacity(16 + 2 + key.len());
        out.extend_from_slice(self.transfer_id.as_bytes());
        let mut tmp = [0u8; 10];
        let n = varint::encode_varint(key.len() as u64, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
        out.extend_from_slice(key);
        Ok(Bytes::from(out))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 {
            return Err(ProtocolError::Malformed("RESUME: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("RESUME: bad transfer_id"))?;
        let (klen, consumed) = varint::decode_varint(&buf[16..])?;
        let i = 16 + consumed;
        let klen_us: usize = klen
            .try_into()
            .map_err(|_| ProtocolError::Malformed("RESUME: key too long"))?;
        if buf.len() < i + klen_us {
            return Err(ProtocolError::Malformed("RESUME: truncated key"));
        }
        let key = std::str::from_utf8(&buf[i..i + klen_us])
            .map_err(|_| ProtocolError::Malformed("RESUME: key not UTF-8"))?
            .to_string();
        Ok(Self {
            transfer_id,
            idempotency_key: key,
        })
    }
}

/// `RESUME_STATE` payload (server → client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeState {
    pub transfer_id: TransferId,
    pub staging_relpath: String,
    pub file_size: u64,
    pub bytes_completed: u64,
    pub verified_up_to: u64,
    pub file_hash: Hash,
    pub completed_chunks: Vec<u64>,
}

impl ResumeState {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        if self.completed_chunks.len() as u64 > MAX_WIRE_CHUNKS {
            return Err(ProtocolError::Malformed("too many completed chunks"));
        }
        let path = self.staging_relpath.as_bytes();
        if path.len() > u16::MAX as usize {
            return Err(ProtocolError::Malformed("RESUME_STATE: path too long"));
        }
        let mut out = Vec::with_capacity(16 + 2 + path.len() + 8 * 3 + 32 + 11);
        out.extend_from_slice(self.transfer_id.as_bytes());
        let mut tmp = [0u8; 10];
        let n = varint::encode_varint(path.len() as u64, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
        out.extend_from_slice(path);
        out.extend_from_slice(&self.file_size.to_le_bytes());
        out.extend_from_slice(&self.bytes_completed.to_le_bytes());
        out.extend_from_slice(&self.verified_up_to.to_le_bytes());
        out.extend_from_slice(self.file_hash.as_bytes());
        let n = varint::encode_varint(self.completed_chunks.len() as u64, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
        for &idx in &self.completed_chunks {
            let n = varint::encode_varint(idx, &mut tmp);
            out.extend_from_slice(&tmp[..n]);
        }
        Ok(Bytes::from(out))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 {
            return Err(ProtocolError::Malformed("RESUME_STATE: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("RESUME_STATE: bad transfer_id"))?;
        let mut i = 16;
        let (plen, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        let plen_us: usize = plen
            .try_into()
            .map_err(|_| ProtocolError::Malformed("RESUME_STATE: path too long"))?;
        if buf.len() < i + plen_us + 8 * 3 + 32 {
            return Err(ProtocolError::Malformed("RESUME_STATE: truncated body"));
        }
        let path = std::str::from_utf8(&buf[i..i + plen_us])
            .map_err(|_| ProtocolError::Malformed("RESUME_STATE: path not UTF-8"))?
            .to_string();
        i += plen_us;
        let file_size = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let bytes_completed = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let verified_up_to = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let file_hash = Hash::from_bytes(&buf[i..i + 32])
            .ok_or_else(|| ProtocolError::Malformed("RESUME_STATE: bad hash"))?;
        i += 32;
        let (count, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        if count > MAX_WIRE_CHUNKS {
            return Err(ProtocolError::Malformed("too many completed chunks"));
        }
        let mut completed = Vec::with_capacity(count as usize);
        let mut prev: Option<u64> = None;
        for _ in 0..count {
            if i >= buf.len() {
                return Err(ProtocolError::Malformed("RESUME_STATE: truncated chunks"));
            }
            let (idx, consumed) = varint::decode_varint(&buf[i..])?;
            i += consumed;
            if let Some(p) = prev {
                if idx <= p {
                    return Err(ProtocolError::Malformed(
                        "RESUME_STATE: non-monotonic chunks",
                    ));
                }
            }
            completed.push(idx);
            prev = Some(idx);
        }
        Ok(Self {
            transfer_id,
            staging_relpath: path,
            file_size,
            bytes_completed,
            verified_up_to,
            file_hash,
            completed_chunks: completed,
        })
    }
}

/// `CANCEL` payload (client → server). User-initiated cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancel {
    pub transfer_id: TransferId,
    pub reason_code: u32,
}

impl Cancel {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 4);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(&self.reason_code.to_le_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 4 {
            return Err(ProtocolError::Malformed("CANCEL: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("CANCEL: bad transfer_id"))?;
        let reason_code = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        Ok(Self {
            transfer_id,
            reason_code,
        })
    }
}

/// `STAT` query (client → server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatQuery {
    pub transfer_id: TransferId,
}

impl StatQuery {
    pub fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(self.transfer_id.as_bytes());
        Bytes::from(out)
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 {
            return Err(ProtocolError::Malformed("STAT: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("STAT: bad transfer_id"))?;
        Ok(Self { transfer_id })
    }
}

/// `STAT_RESULT` payload (server → client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatResult {
    pub transfer_id: TransferId,
    pub found: bool,
    pub status: String,
    pub direction: String,
    pub remote_path: String,
    pub file_size: u64,
    pub bytes_completed: u64,
    pub verified_up_to: u64,
    pub created_ms: u64,
    pub updated_ms: u64,
}

impl StatResult {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 1 + 8 * 5 + 30);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.push(self.found as u8);
        out.push(0); // padding for alignment
        let mut tmp = [0u8; 10];
        for s in [&self.status, &self.direction, &self.remote_path] {
            let b = s.as_bytes();
            if b.len() > u16::MAX as usize {
                return Err(ProtocolError::Malformed("STAT_RESULT: field too long"));
            }
            let n = varint::encode_varint(b.len() as u64, &mut tmp);
            out.extend_from_slice(&tmp[..n]);
            out.extend_from_slice(b);
        }
        out.extend_from_slice(&self.file_size.to_le_bytes());
        out.extend_from_slice(&self.bytes_completed.to_le_bytes());
        out.extend_from_slice(&self.verified_up_to.to_le_bytes());
        out.extend_from_slice(&self.created_ms.to_le_bytes());
        out.extend_from_slice(&self.updated_ms.to_le_bytes());
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 2 {
            return Err(ProtocolError::Malformed("STAT_RESULT: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[..16])
            .ok_or_else(|| ProtocolError::Malformed("STAT_RESULT: bad transfer_id"))?;
        let found = match buf[16] {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::Malformed("STAT_RESULT: bad found flag")),
        };
        let mut i = 18;
        let mut read_str = |buf: &[u8], i: &mut usize| -> Result<String, ProtocolError> {
            let (n, c) = varint::decode_varint(&buf[*i..])?;
            *i += c;
            let n_us: usize = n
                .try_into()
                .map_err(|_| ProtocolError::Malformed("STAT_RESULT: string too long"))?;
            if buf.len() < *i + n_us {
                return Err(ProtocolError::Malformed("STAT_RESULT: truncated string"));
            }
            let s = std::str::from_utf8(&buf[*i..*i + n_us])
                .map_err(|_| ProtocolError::Malformed("STAT_RESULT: not UTF-8"))?
                .to_string();
            *i += n_us;
            Ok(s)
        };
        let status = read_str(buf, &mut i)?;
        let direction = read_str(buf, &mut i)?;
        let remote_path = read_str(buf, &mut i)?;
        if buf.len() < i + 8 * 5 {
            return Err(ProtocolError::Malformed("STAT_RESULT: truncated numbers"));
        }
        let file_size = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let bytes_completed = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let verified_up_to = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let created_ms = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        i += 8;
        let updated_ms = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        Ok(Self {
            transfer_id,
            found,
            status,
            direction,
            remote_path,
            file_size,
            bytes_completed,
            verified_up_to,
            created_ms,
            updated_ms,
        })
    }
}

/// `LIST` query (client → server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListQuery {
    pub url_prefix: String,
}

impl ListQuery {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let p = self.url_prefix.as_bytes();
        if p.len() > u16::MAX as usize {
            return Err(ProtocolError::Malformed("LIST: prefix too long"));
        }
        let mut out = Vec::with_capacity(2 + p.len());
        let mut tmp = [0u8; 10];
        let n = varint::encode_varint(p.len() as u64, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
        out.extend_from_slice(p);
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        let (n, c) = varint::decode_varint(buf)?;
        let mut i = c;
        let n_us: usize = n
            .try_into()
            .map_err(|_| ProtocolError::Malformed("LIST: prefix too long"))?;
        if buf.len() < i + n_us {
            return Err(ProtocolError::Malformed("LIST: truncated prefix"));
        }
        let url_prefix = std::str::from_utf8(&buf[i..i + n_us])
            .map_err(|_| ProtocolError::Malformed("LIST: not UTF-8"))?
            .to_string();
        Ok(Self { url_prefix })
    }
}

/// `LIST_RESULT` payload (server → client). Length-prefixed list of
/// `StatResult` (each prefixed with its own varint length so a
/// decoder can find entry boundaries without re-encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListResult {
    pub entries: Vec<StatResult>,
}

impl ListResult {
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        if self.entries.len() as u64 > MAX_WIRE_CHUNKS {
            return Err(ProtocolError::Malformed("LIST_RESULT: too many entries"));
        }
        let mut out = Vec::new();
        let mut tmp = [0u8; 10];
        let n = varint::encode_varint(self.entries.len() as u64, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
        for e in &self.entries {
            let body = e.encode()?;
            let n = varint::encode_varint(body.len() as u64, &mut tmp);
            out.extend_from_slice(&tmp[..n]);
            out.extend_from_slice(&body);
        }
        Ok(Bytes::from(out))
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        let (count, c) = varint::decode_varint(buf)?;
        if count > MAX_WIRE_CHUNKS {
            return Err(ProtocolError::Malformed("LIST_RESULT: too many entries"));
        }
        let mut i = c;
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if i >= buf.len() {
                return Err(ProtocolError::Malformed(
                    "LIST_RESULT: truncated entry length",
                ));
            }
            let (n, c) = varint::decode_varint(&buf[i..])?;
            i += c;
            let n_us: usize = n
                .try_into()
                .map_err(|_| ProtocolError::Malformed("LIST_RESULT: entry too long"))?;
            if buf.len() < i + n_us {
                return Err(ProtocolError::Malformed("LIST_RESULT: truncated entry"));
            }
            let entry = StatResult::decode(&buf[i..i + n_us])?;
            i += n_us;
            entries.push(entry);
        }
        Ok(Self { entries })
    }
}

/// `MANIFEST_BEGIN` (0x30, sender → receiver).
///
/// Declares the total file count, total transfer bytes, negotiated chunker
/// parameters, and the BLAKE3 digest of the canonical manifest content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBegin {
    /// Declared file count in this manifest. Bounded by `MAX_MANIFEST_ENTRIES`.
    pub file_count: u64,
    /// Declared total uncompressed bytes across all files. Bounded by `MAX_MANIFEST_BYTES`.
    pub total_bytes: u64,
    /// Chunker parameters used to chunk the files described in this manifest.
    pub chunker_params: ChunkParams,
    /// BLAKE3 digest over the canonical uncompressed `FileEntry` sequence.
    pub manifest_hash: Hash,
}

impl ManifestBegin {
    /// Encode to binary payload (72 bytes).
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(72);
        out.extend_from_slice(&self.file_count.to_le_bytes());
        out.extend_from_slice(&self.total_bytes.to_le_bytes());
        out.extend_from_slice(&self.chunker_params.min.to_le_bytes());
        out.extend_from_slice(&self.chunker_params.target.to_le_bytes());
        out.extend_from_slice(&self.chunker_params.max.to_le_bytes());
        out.extend_from_slice(self.manifest_hash.as_bytes());
        Ok(Bytes::from(out))
    }

    /// Decode from binary payload.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 72 {
            return Err(ProtocolError::Malformed("MANIFEST_BEGIN: truncated"));
        }
        let file_count = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        if file_count > MAX_MANIFEST_ENTRIES {
            return Err(ProtocolError::InvalidManifest(format!(
                "file count {file_count} exceeds MAX_MANIFEST_ENTRIES {MAX_MANIFEST_ENTRIES}"
            )));
        }
        let total_bytes = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        if total_bytes > MAX_MANIFEST_BYTES {
            return Err(ProtocolError::InvalidManifest(format!(
                "total bytes {total_bytes} exceeds MAX_MANIFEST_BYTES {MAX_MANIFEST_BYTES}"
            )));
        }
        let min = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let target = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let max = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let chunker_params = ChunkParams::new(min, target, max)
            .ok_or_else(|| ProtocolError::Malformed("MANIFEST_BEGIN: invalid chunk params"))?;
        let manifest_hash = Hash::from_bytes(&buf[40..72])
            .ok_or_else(|| ProtocolError::Malformed("MANIFEST_BEGIN: invalid hash"))?;

        Ok(Self {
            file_count,
            total_bytes,
            chunker_params,
            manifest_hash,
        })
    }
}

/// `MANIFEST_BATCH` (0x31, sender → receiver).
///
/// Carries up to 4096 file/chunk entries in a single frame. The payload is
/// zstd-framed binary bytes representing the canonical encoding of the entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBatch {
    /// Zero-based sequential batch index.
    pub batch_index: u64,
    /// Number of entries contained in this batch (up to `MANIFEST_BATCH_SIZE`).
    pub entry_count: u32,
    /// zstd-compressed payload containing canonical FileEntry bytes.
    pub compressed_payload: Bytes,
}

impl ManifestBatch {
    /// Encode to binary payload.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(12 + self.compressed_payload.len());
        out.extend_from_slice(&self.batch_index.to_le_bytes());
        out.extend_from_slice(&self.entry_count.to_le_bytes());
        out.extend_from_slice(&self.compressed_payload);
        Ok(Bytes::from(out))
    }

    /// Decode from binary payload.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 12 {
            return Err(ProtocolError::Malformed("MANIFEST_BATCH: truncated"));
        }
        let batch_index = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let entry_count = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if entry_count as usize > MANIFEST_BATCH_SIZE {
            return Err(ProtocolError::InvalidManifest(format!(
                "batch entry count {entry_count} exceeds MANIFEST_BATCH_SIZE {MANIFEST_BATCH_SIZE}"
            )));
        }
        let compressed_payload = Bytes::copy_from_slice(&buf[12..]);
        Ok(Self {
            batch_index,
            entry_count,
            compressed_payload,
        })
    }
}

/// `MANIFEST_END` (0x32, sender → receiver).
///
/// Marks the end of the manifest exchange. Carries the final BLAKE3 digest,
/// which MUST match the digest declared in `MANIFEST_BEGIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEnd {
    /// BLAKE3 digest over the entire canonical manifest stream.
    pub manifest_hash: Hash,
}

impl ManifestEnd {
    /// Encode to binary payload (32 bytes).
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        Ok(Bytes::copy_from_slice(self.manifest_hash.as_bytes()))
    }

    /// Decode from binary payload.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() != 32 {
            return Err(ProtocolError::Malformed("MANIFEST_END: expected 32 bytes"));
        }
        let manifest_hash = Hash::from_bytes(buf)
            .ok_or_else(|| ProtocolError::Malformed("MANIFEST_END: invalid hash"))?;
        Ok(Self { manifest_hash })
    }
}

/// `INVENTORY_HINT` (0x33, receiver → sender).
///
/// Optional probabilistic filter (Bloom filter) over chunks the receiver holds,
/// allowing the sender to skip querying chunks that are definitely absent (`PROTOCOL.md` §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryHint {
    /// Associated transfer identifier.
    pub transfer_id: TransferId,
    /// Declared number of bits in the filter bitset.
    pub filter_bits: u32,
    /// Number of hash functions used.
    pub num_hashes: u8,
    /// Filter bitset payload.
    pub bitset: Bytes,
}

impl InventoryHint {
    /// Encode to binary payload.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 4 + 1 + self.bitset.len());
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(&self.filter_bits.to_le_bytes());
        out.push(self.num_hashes);
        out.extend_from_slice(&self.bitset);
        Ok(Bytes::from(out))
    }

    /// Decode from binary payload.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 4 + 1 {
            return Err(ProtocolError::Malformed("INVENTORY_HINT: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[0..16])
            .ok_or_else(|| ProtocolError::Malformed("INVENTORY_HINT: bad transfer_id"))?;
        let filter_bits = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let num_hashes = buf[20];
        let bitset = Bytes::copy_from_slice(&buf[21..]);
        Ok(Self {
            transfer_id,
            filter_bits,
            num_hashes,
            bitset,
        })
    }
}

/// `CHUNK_QUERY` (0x34, sender → receiver).
///
/// A batch of chunk hashes queried against the receiver's inventory (`PROTOCOL.md` §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkQuery {
    /// Associated transfer identifier.
    pub transfer_id: TransferId,
    /// Query sequence index.
    pub query_seq: u64,
    /// Hashes of chunks being queried.
    pub chunk_hashes: Vec<Hash>,
}

impl ChunkQuery {
    /// Encode to binary payload.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 8 + 8 + self.chunk_hashes.len() * 32);
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(&self.query_seq.to_le_bytes());
        let mut tmp = [0u8; 10];
        let n = varint::encode_varint(self.chunk_hashes.len() as u64, &mut tmp);
        out.extend_from_slice(&tmp[..n]);
        for h in &self.chunk_hashes {
            out.extend_from_slice(h.as_bytes());
        }
        Ok(Bytes::from(out))
    }

    /// Decode from binary payload.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 8 {
            return Err(ProtocolError::Malformed("CHUNK_QUERY: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[0..16])
            .ok_or_else(|| ProtocolError::Malformed("CHUNK_QUERY: bad transfer_id"))?;
        let query_seq = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let mut i = 24;
        let (count, consumed) = varint::decode_varint(&buf[i..])?;
        i += consumed;
        if count > MAX_MANIFEST_ENTRIES {
            return Err(ProtocolError::Malformed("CHUNK_QUERY: too many hashes"));
        }
        let count_us = count as usize;
        if buf.len() < i + count_us * 32 {
            return Err(ProtocolError::Malformed("CHUNK_QUERY: truncated hashes"));
        }
        let mut chunk_hashes = Vec::with_capacity(count_us);
        for _ in 0..count_us {
            let h = Hash::from_bytes(&buf[i..i + 32])
                .ok_or_else(|| ProtocolError::Malformed("CHUNK_QUERY: invalid hash"))?;
            chunk_hashes.push(h);
            i += 32;
        }
        Ok(Self {
            transfer_id,
            query_seq,
            chunk_hashes,
        })
    }
}

/// `CHUNK_RESPONSE` (0x35, receiver → sender).
///
/// An RLE-encoded bitmap of have (1) / need (0) status matching the query order (`PROTOCOL.md` §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkResponse {
    /// Associated transfer identifier.
    pub transfer_id: TransferId,
    /// Query sequence matching the corresponding [`ChunkQuery`].
    pub query_seq: u64,
    /// Total number of chunks covered by this response.
    pub total_chunks: u32,
    /// Number of chunks the receiver already has.
    pub have_count: u32,
    /// Run-length encoded bitmap payload.
    pub rle_bitmap: Bytes,
}

impl ChunkResponse {
    /// Encode to binary payload.
    pub fn encode(&self) -> Result<Bytes, ProtocolError> {
        let mut out = Vec::with_capacity(16 + 8 + 4 + 4 + self.rle_bitmap.len());
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(&self.query_seq.to_le_bytes());
        out.extend_from_slice(&self.total_chunks.to_le_bytes());
        out.extend_from_slice(&self.have_count.to_le_bytes());
        out.extend_from_slice(&self.rle_bitmap);
        Ok(Bytes::from(out))
    }

    /// Decode from binary payload.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 16 + 8 + 4 + 4 {
            return Err(ProtocolError::Malformed("CHUNK_RESPONSE: truncated"));
        }
        let transfer_id = TransferId::from_bytes(&buf[0..16])
            .ok_or_else(|| ProtocolError::Malformed("CHUNK_RESPONSE: bad transfer_id"))?;
        let query_seq = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let total_chunks = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let have_count = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        let rle_bitmap = Bytes::copy_from_slice(&buf[32..]);
        Ok(Self {
            transfer_id,
            query_seq,
            total_chunks,
            have_count,
            rle_bitmap,
        })
    }
}

/// A decoded, typed message body. The frame header has already been parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `HELLO`.
    Hello(Hello),
    /// `HELLO_ACK`.
    HelloAck(HelloAck),
    /// `AUTH` (client → server). M4.
    Auth(Auth),
    /// `AUTH_OK` (server → client). M4.
    AuthOk(AuthOk),
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
    /// `CHECKPOINT` (sender → receiver). M3.
    Checkpoint(Checkpoint),
    /// `RESUME` (client → server). M3.
    Resume(Resume),
    /// `RESUME_STATE` (server → client). M3.
    ResumeState(ResumeState),
    /// `CANCEL` (client → server). M3.
    Cancel(Cancel),
    /// `STAT` query (client → server). M3.
    Stat(StatQuery),
    /// `STAT_RESULT` (server → client). M3.
    StatResult(StatResult),
    /// `LIST` query (client → server). M3.
    List(ListQuery),
    /// `LIST_RESULT` (server → client). M3.
    ListResult(ListResult),
    /// `MANIFEST_BEGIN` (sender → receiver). M5.
    ManifestBegin(ManifestBegin),
    /// `MANIFEST_BATCH` (sender → receiver). M5.
    ManifestBatch(ManifestBatch),
    /// `MANIFEST_END` (sender → receiver). M5.
    ManifestEnd(ManifestEnd),
    /// `INVENTORY_HINT` (receiver → sender). M7.
    InventoryHint(InventoryHint),
    /// `CHUNK_QUERY` (sender → receiver). M7.
    ChunkQuery(ChunkQuery),
    /// `CHUNK_RESPONSE` (receiver → sender). M7.
    ChunkResponse(ChunkResponse),
}

impl Message {
    /// Return the wire type byte for this message.
    pub fn type_byte(&self) -> u8 {
        match self {
            Message::Hello(_) => HELLO,
            Message::HelloAck(_) => HELLO_ACK,
            Message::Auth(_) => AUTH,
            Message::AuthOk(_) => AUTH_OK,
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
            Message::Checkpoint(_) => CHECKPOINT,
            Message::Resume(_) => RESUME,
            Message::ResumeState(_) => RESUME_STATE,
            Message::Cancel(_) => CANCEL,
            Message::Stat(_) => STAT,
            Message::StatResult(_) => STAT_RESULT,
            Message::List(_) => LIST,
            Message::ListResult(_) => LIST_RESULT,
            Message::ManifestBegin(_) => MANIFEST_BEGIN,
            Message::ManifestBatch(_) => MANIFEST_BATCH,
            Message::ManifestEnd(_) => MANIFEST_END,
            Message::InventoryHint(_) => INVENTORY_HINT,
            Message::ChunkQuery(_) => CHUNK_QUERY,
            Message::ChunkResponse(_) => CHUNK_RESPONSE,
        }
    }

    /// Encode the payload (no frame header). Returns `(type_byte, payload)`.
    pub fn encode(&self) -> Result<(u8, Bytes), ProtocolError> {
        match self {
            Message::Hello(h) => Ok((HELLO, h.encode()?)),
            Message::HelloAck(h) => Ok((HELLO_ACK, h.encode()?)),
            Message::Auth(a) => Ok((AUTH, a.encode()?)),
            Message::AuthOk(a) => Ok((AUTH_OK, a.encode()?)),
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
            Message::Checkpoint(m) => Ok((CHECKPOINT, m.encode()?)),
            Message::Resume(m) => Ok((RESUME, m.encode()?)),
            Message::ResumeState(m) => Ok((RESUME_STATE, m.encode()?)),
            Message::Cancel(m) => Ok((CANCEL, m.encode()?)),
            Message::Stat(m) => Ok((STAT, m.encode())),
            Message::StatResult(m) => Ok((STAT_RESULT, m.encode()?)),
            Message::List(m) => Ok((LIST, m.encode()?)),
            Message::ListResult(m) => Ok((LIST_RESULT, m.encode()?)),
            Message::ManifestBegin(m) => Ok((MANIFEST_BEGIN, m.encode()?)),
            Message::ManifestBatch(m) => Ok((MANIFEST_BATCH, m.encode()?)),
            Message::ManifestEnd(m) => Ok((MANIFEST_END, m.encode()?)),
            Message::InventoryHint(m) => Ok((INVENTORY_HINT, m.encode()?)),
            Message::ChunkQuery(m) => Ok((CHUNK_QUERY, m.encode()?)),
            Message::ChunkResponse(m) => Ok((CHUNK_RESPONSE, m.encode()?)),
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
            CHECKPOINT => Ok(Message::Checkpoint(Checkpoint::decode(payload)?)),
            RESUME => Ok(Message::Resume(Resume::decode(payload)?)),
            RESUME_STATE => Ok(Message::ResumeState(ResumeState::decode(payload)?)),
            CANCEL => Ok(Message::Cancel(Cancel::decode(payload)?)),
            STAT => Ok(Message::Stat(StatQuery::decode(payload)?)),
            STAT_RESULT => Ok(Message::StatResult(StatResult::decode(payload)?)),
            LIST => Ok(Message::List(ListQuery::decode(payload)?)),
            LIST_RESULT => Ok(Message::ListResult(ListResult::decode(payload)?)),
            MANIFEST_BEGIN => Ok(Message::ManifestBegin(ManifestBegin::decode(payload)?)),
            MANIFEST_BATCH => Ok(Message::ManifestBatch(ManifestBatch::decode(payload)?)),
            MANIFEST_END => Ok(Message::ManifestEnd(ManifestEnd::decode(payload)?)),
            INVENTORY_HINT => Ok(Message::InventoryHint(InventoryHint::decode(payload)?)),
            CHUNK_QUERY => Ok(Message::ChunkQuery(ChunkQuery::decode(payload)?)),
            CHUNK_RESPONSE => Ok(Message::ChunkResponse(ChunkResponse::decode(payload)?)),
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
        let p = Ping {
            nonce: 0xDEAD_BEEF,
            sender_ts_ms: 1234,
        };
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
        let b = Bye {
            code: ErrorCode::TransferCancelled.to_wire(),
        };
        let buf = b.encode();
        let b2 = Bye::decode(&buf).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn session_init_roundtrip() {
        let s = SessionOptions {
            bandwidth_bps: 1_000_000,
            priority: 7,
        };
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
        assert_eq!(TransferOp::from_wire(3).unwrap(), TransferOp::SyncUpload);
        assert_eq!(TransferOp::from_wire(4).unwrap(), TransferOp::SyncDownload);
        assert_eq!(TransferOp::from_wire(5).unwrap(), TransferOp::Delete);
        assert!(TransferOp::from_wire(0).is_err());
        assert!(TransferOp::from_wire(99).is_err());
    }

    #[test]
    fn checkpoint_roundtrip() {
        let cp = Checkpoint {
            transfer_id: TransferId::generate(),
            bytes_transferred: 1_000_000,
            verified_up_to: 512_000,
            ts_ms: 1234,
            completed_chunks: vec![0, 1, 2, 3, 4],
        };
        let buf = cp.encode().unwrap();
        let cp2 = Checkpoint::decode(&buf).unwrap();
        assert_eq!(cp, cp2);
    }

    #[test]
    fn checkpoint_rejects_non_monotonic() {
        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(&1000u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        let mut tmp = [0u8; 10];
        let n = varint::encode_varint(2, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);
        let n = varint::encode_varint(5, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);
        let n = varint::encode_varint(3, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);
        assert!(Checkpoint::decode(&buf).is_err());
    }

    #[test]
    fn resume_roundtrip() {
        let r = Resume {
            transfer_id: TransferId::generate(),
            idempotency_key: "abc-123".into(),
        };
        let buf = r.encode().unwrap();
        let r2 = Resume::decode(&buf).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn resume_state_roundtrip() {
        let r = ResumeState {
            transfer_id: TransferId::generate(),
            staging_relpath: "x/1.velcrux-partial".into(),
            file_size: 10_000_000,
            bytes_completed: 4_000_000,
            verified_up_to: 0,
            file_hash: Hash::of(b"hello"),
            completed_chunks: vec![0, 1, 2],
        };
        let buf = r.encode().unwrap();
        let r2 = ResumeState::decode(&buf).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn cancel_roundtrip() {
        let c = Cancel {
            transfer_id: TransferId::generate(),
            reason_code: 5000,
        };
        let buf = c.encode().unwrap();
        let c2 = Cancel::decode(&buf).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn stat_query_roundtrip() {
        let q = StatQuery {
            transfer_id: TransferId::generate(),
        };
        let buf = q.encode();
        let q2 = StatQuery::decode(&buf).unwrap();
        assert_eq!(q, q2);
    }

    #[test]
    fn stat_result_roundtrip() {
        let r = StatResult {
            transfer_id: TransferId::generate(),
            found: true,
            status: "active".into(),
            direction: "upload".into(),
            remote_path: "data/x.bin".into(),
            file_size: 12345,
            bytes_completed: 6000,
            verified_up_to: 0,
            created_ms: 1,
            updated_ms: 2,
        };
        let buf = r.encode().unwrap();
        let r2 = StatResult::decode(&buf).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn list_query_roundtrip() {
        let q = ListQuery {
            url_prefix: "data/".into(),
        };
        let buf = q.encode().unwrap();
        let q2 = ListQuery::decode(&buf).unwrap();
        assert_eq!(q, q2);
    }

    #[test]
    fn list_result_roundtrip() {
        let r = ListResult {
            entries: vec![
                StatResult {
                    transfer_id: TransferId::generate(),
                    found: true,
                    status: "active".into(),
                    direction: "upload".into(),
                    remote_path: "data/a.bin".into(),
                    file_size: 1,
                    bytes_completed: 0,
                    verified_up_to: 0,
                    created_ms: 1,
                    updated_ms: 2,
                },
                StatResult {
                    transfer_id: TransferId::generate(),
                    found: true,
                    status: "committed".into(),
                    direction: "download".into(),
                    remote_path: "data/b.bin".into(),
                    file_size: 2,
                    bytes_completed: 2,
                    verified_up_to: 2,
                    created_ms: 3,
                    updated_ms: 4,
                },
            ],
        };
        let buf = r.encode().unwrap();
        let r2 = ListResult::decode(&buf).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn message_enum_full_roundtrip() {
        let cases = vec![
            Message::Checkpoint(Checkpoint {
                transfer_id: TransferId::generate(),
                bytes_transferred: 1,
                verified_up_to: 0,
                ts_ms: 0,
                completed_chunks: vec![0],
            }),
            Message::Resume(Resume {
                transfer_id: TransferId::generate(),
                idempotency_key: "k".into(),
            }),
            Message::Cancel(Cancel {
                transfer_id: TransferId::generate(),
                reason_code: 5000,
            }),
            Message::Stat(StatQuery {
                transfer_id: TransferId::generate(),
            }),
        ];
        for m in cases {
            let (tb, p) = m.encode().unwrap();
            let m2 = Message::decode(tb, &p).unwrap();
            assert_eq!(m, m2);
        }
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
        let m = Verify {
            transfer_id: tid,
            expected_hash: Hash::of(b"x"),
        };
        let buf = m.encode().unwrap();
        let m2 = Verify::decode(&buf).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn verify_result_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let m = VerifyResult {
            transfer_id: tid,
            ok: true,
            computed_hash: Hash::of(b"x"),
        };
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
        let m = Committed {
            transfer_id: tid,
            files: 1,
        };
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
            Message::Verify(Verify {
                transfer_id: tid,
                expected_hash: Hash::ZERO,
            }),
            Message::VerifyResult(VerifyResult {
                transfer_id: tid,
                ok: true,
                computed_hash: Hash::ZERO,
            }),
            Message::Commit(Commit { transfer_id: tid }),
            Message::Committed(Committed {
                transfer_id: tid,
                files: 1,
            }),
            Message::ManifestBegin(ManifestBegin {
                file_count: 42,
                total_bytes: 1024 * 1024 * 10,
                chunker_params: ChunkParams::default(),
                manifest_hash: Hash::ZERO,
            }),
            Message::ManifestBatch(ManifestBatch {
                batch_index: 1,
                entry_count: 10,
                compressed_payload: Bytes::from_static(b"compressed_data"),
            }),
            Message::ManifestEnd(ManifestEnd {
                manifest_hash: Hash::ZERO,
            }),
            Message::InventoryHint(InventoryHint {
                transfer_id: tid,
                filter_bits: 64,
                num_hashes: 3,
                bitset: Bytes::from_static(&[0xFF; 8]),
            }),
            Message::ChunkQuery(ChunkQuery {
                transfer_id: tid,
                query_seq: 1,
                chunk_hashes: vec![Hash::ZERO, Hash::from_bytes(&[1u8; 32]).unwrap()],
            }),
            Message::ChunkResponse(ChunkResponse {
                transfer_id: tid,
                query_seq: 1,
                total_chunks: 2,
                have_count: 1,
                rle_bitmap: Bytes::from_static(&[0x01, 0x01]),
            }),
        ];
        for m in cases {
            let (tb, payload) = m.encode().unwrap();
            let m2 = Message::decode(tb, &payload).unwrap();
            assert_eq!(m, m2);
        }
    }

    #[test]
    fn manifest_messages_roundtrip() {
        let begin = ManifestBegin {
            file_count: 1000,
            total_bytes: 50_000_000,
            chunker_params: ChunkParams::new(128 * 1024, 512 * 1024, 2 * 1024 * 1024).unwrap(),
            manifest_hash: Hash::from_bytes(&[7u8; 32]).unwrap(),
        };
        let bytes = begin.encode().unwrap();
        let decoded = ManifestBegin::decode(&bytes).unwrap();
        assert_eq!(begin, decoded);

        let batch = ManifestBatch {
            batch_index: 3,
            entry_count: 4096,
            compressed_payload: Bytes::from_static(b"payload_bytes"),
        };
        let bytes = batch.encode().unwrap();
        let decoded = ManifestBatch::decode(&bytes).unwrap();
        assert_eq!(batch, decoded);

        let end = ManifestEnd {
            manifest_hash: Hash::from_bytes(&[9u8; 32]).unwrap(),
        };
        let bytes = end.encode().unwrap();
        let decoded = ManifestEnd::decode(&bytes).unwrap();
        assert_eq!(end, decoded);
    }

    #[test]
    fn delta_messages_roundtrip() {
        let tid = crate::util::TransferId::generate();

        let hint = InventoryHint {
            transfer_id: tid,
            filter_bits: 128,
            num_hashes: 4,
            bitset: Bytes::from_static(&[0xAA; 16]),
        };
        let bytes = hint.encode().unwrap();
        let decoded = InventoryHint::decode(&bytes).unwrap();
        assert_eq!(hint, decoded);

        let query = ChunkQuery {
            transfer_id: tid,
            query_seq: 42,
            chunk_hashes: vec![
                Hash::from_bytes(&[1u8; 32]).unwrap(),
                Hash::from_bytes(&[2u8; 32]).unwrap(),
                Hash::from_bytes(&[3u8; 32]).unwrap(),
            ],
        };
        let bytes = query.encode().unwrap();
        let decoded = ChunkQuery::decode(&bytes).unwrap();
        assert_eq!(query, decoded);

        let resp = ChunkResponse {
            transfer_id: tid,
            query_seq: 42,
            total_chunks: 100,
            have_count: 95,
            rle_bitmap: Bytes::from_static(&[0x5F, 0x05]),
        };
        let bytes = resp.encode().unwrap();
        let decoded = ChunkResponse::decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }
}
