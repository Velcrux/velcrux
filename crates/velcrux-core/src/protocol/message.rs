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
}





