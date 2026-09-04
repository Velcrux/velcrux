//! Wire protocol: encoding, decoding, message catalog.
//!
//! No I/O. No filesystem. No allocation driven by attacker-supplied lengths.
//! Every decoder is a pure function over `&[u8]` so it can be fuzzed in
//! isolation (DEVELOPMENT.md §6, SECURITY.md §1).
//!
//! Layout follows `PROTOCOL.md`:
//!   - §1  conventions (LE, LEB128 varint, u64 sizes, canonical varints)
//!   - §3  framing (control + data)
//!   - §4  message catalog
//!   - §6  capability bitset
//!   - §10 wire error codes

pub mod capabilities;
pub mod error;
pub mod frame;
pub mod limits;
pub mod message;
pub mod varint;

pub use capabilities::{Capability, Capabilities};
pub use error::{ErrorCode, ErrorDetail, ERROR_CODE_NAMES};
pub use frame::{Frame, FrameFlags, FRAME_HEADER_LEN};
pub use limits::*;
pub use message::{
    Hello, HelloAck, Limits, Message, Ping, Pong, SessionInit, SessionOptions, AGENT,
    HELLO_ACK, HELLO, PING, PONG, SESSION_INIT, BYE,
};
pub use varint::{decode_varint, encode_varint, varint_len};
